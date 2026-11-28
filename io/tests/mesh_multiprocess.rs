//! Final Acceptance Gate: 5-Process Autonomous Recovery & Host-Clock Fencing Test
//!
//! Spawns **5 independent OS processes** (3 voter/resource processes + 2 durable coordinator
//! processes, each with its own on-disk `redb` database and TCP socket):
//! 1. Competing coordinators (`coord-1` vs `coord-2`) race `slot=1` concurrently -> at most ONE commits.
//! 2. **Decisive autonomous recovery:**
//!    - Winning coordinator gathers quorum (2 of 3) on `slot=2` (voters durably persist BOTH
//!      `SignedVote` and canonical `LeaseProposal`) with `skip_persist = true`, then is **KILLED
//!      PERMANENTLY (never restarted, never resubmits!)**.
//!    - Standby coordinator (`coord-2`) queries all 3 voters over TCP, runs `recover_and_commit_slot`,
//!      reconstructs the exact `FencedLease`, and **commits it to its own durable `redb` database**
//!      (advancing `next_slot` to 3 and `max_fencing_epoch` to 2).
//!    - Standby coordinator is **killed and restarted from its on-disk DB** -> verifies the
//!      recovered lease AND `next_slot == 3` survive restart!
//! 3. Recovered lease is installed on `node-3` using **host-trusted clock (`install_lease_now`)**:
//!    - Exact retry is strictly idempotent; +1 ms expiry tampering is rejected; stale `epoch=1` lease
//!      from `slot=1` is rejected!

use nexus_io::db::Database;
use nexus_io::mesh::consensus::{
    ConsensusMode, CoordinationGroup, DurableSlotDecision, EpochInstallReceipt, FencedLease,
    FencedResourceGuard, GroupMember, LeaseProposal, MembershipEpochConfig,
    MembershipTransitionDecision, MembershipTransitionProposal, PrepareTermRequest, SignedVote,
    SlotProposal, TermCertificate, TermPromise, VoteRequest, VoterNode,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum VoterRpcReq {
    Vote(VoteRequest),
    PrepareTerm(PrepareTermRequest),
    /// Authenticated administrative genesis provisioning (strictly separate from membership installation!).
    AdminProvisionGenesis {
        admin_token: String,
        group_id: String,
        mode: ConsensusMode,
        members: Vec<GroupMember>,
    },
    InstallMembershipEpoch {
        decision: MembershipTransitionDecision,
        prev_members: Vec<GroupMember>,
    },
    QueryLock {
        group_id: String,
        epoch: u64,
        slot: u64,
    },
    /// Production-shaped host-clock installation (resource host owns the clock!).
    InstallLeaseNow {
        lease: FencedLease,
        members: Vec<GroupMember>,
    },
    /// Production-shaped host-clock hot-path execution check.
    ExecLocalNow {
        resource_key: String,
        holder_node_id: String,
        fencing_epoch: u64,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum VoterRpcResp {
    VoteOk { vote: SignedVote },
    PromiseOk { promise: TermPromise },
    GenesisProvisioned { genesis_digest: String },
    EpochInstalled { receipt: EpochInstallReceipt },
    LockFound { entry: Option<(SignedVote, Option<SlotProposal>)> },
    ExecOk { accepted_epoch: u64 },
    Err { message: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum CoordRpcReq {
    ProposeAndCommit {
        voter_addrs: Vec<String>,
        lease_id: String,
        resource_key: String,
        holder_node_id: String,
        workload_id: String,
        issued_at_ms: u64,
        expires_at_ms: u64,
        now: u64,
        skip_persist: bool,
    },
    ProposeMembership {
        voter_addrs: Vec<String>,
        new_members: Vec<GroupMember>,
        skip_persist: bool,
    },
    RecoverAndCommitSlot {
        voter_addrs: Vec<String>,
        slot: u64,
    },
    GetState {
        resource_key: String,
    },
    ExpireLocalLease {
        resource_key: String,
        now: u64,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum CoordRpcResp {
    Committed { lease: FencedLease },
    CommittedMembership { decision: MembershipTransitionDecision },
    VotesCollectedOnly { count: usize, proposal_hash: String },
    State { membership_epoch: u64, next_slot: u64, lease: Option<FencedLease> },
    Ok,
    Err { message: String },
}

async fn send_voter_rpc(addr: &str, req: &VoterRpcReq) -> VoterRpcResp {
    let mut stream = TcpStream::connect(addr).await.expect("connect to voter TCP socket");
    let line = format!("{}\n", serde_json::to_string(req).unwrap());
    stream.write_all(line.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    let mut reader = BufReader::new(stream);
    let mut resp_line = String::new();
    reader.read_line(&mut resp_line).await.unwrap();
    serde_json::from_str(resp_line.trim()).expect("valid VoterRpcResp JSON")
}

async fn send_coord_rpc(addr: &str, req: &CoordRpcReq) -> CoordRpcResp {
    let mut stream = TcpStream::connect(addr).await.expect("connect to coordinator TCP socket");
    let line = format!("{}\n", serde_json::to_string(req).unwrap());
    stream.write_all(line.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    let mut reader = BufReader::new(stream);
    let mut resp_line = String::new();
    reader.read_line(&mut resp_line).await.unwrap();
    serde_json::from_str(resp_line.trim()).expect("valid CoordRpcResp JSON")
}

async fn fan_out_votes_tcp(addrs: &[String], req: VoteRequest) -> Vec<SignedVote> {
    let mut set = tokio::task::JoinSet::new();
    for addr in addrs {
        let a = addr.clone();
        let r = req.clone();
        set.spawn(async move { send_voter_rpc(&a, &VoterRpcReq::Vote(r)).await });
    }
    let mut votes = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(VoterRpcResp::VoteOk { vote }) = res {
            votes.push(vote);
        }
    }
    votes
}

async fn run_voter_child() {
    let node_id = std::env::var("NEXUS_CHILD_NODE_ID").unwrap();
    let data_dir = PathBuf::from(std::env::var("NEXUS_CHILD_DATA_DIR").unwrap());
    std::fs::create_dir_all(&data_dir).unwrap();

    let key_path = data_dir.join("node_key.json");
    let (sk, pk): (String, String) = if key_path.exists() {
        let raw = std::fs::read_to_string(&key_path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        (v["sk"].as_str().unwrap().to_string(), v["pk"].as_str().unwrap().to_string())
    } else {
        let (sk, pk) = nexus_db::auth::ed25519_generate_keypair();
        std::fs::write(&key_path, serde_json::json!({ "sk": sk, "pk": pk }).to_string()).unwrap();
        (sk, pk)
    };

    let db = Arc::new(Database::init_in(data_dir.join("db")).await);
    let voter = VoterNode::new(node_id, sk, db.clone()).with_legacy_term_zero_compat();
    let guard = FencedResourceGuard::new(db.clone());
    voter.ensure_tables().await.unwrap();
    guard.ensure_tables().await.unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    println!("READY {} {}", addr, pk);
    use std::io::Write as _;
    std::io::stdout().flush().unwrap();

    let expected_admin_token = std::env::var("NEXUS_BOOTSTRAP_ADMIN_TOKEN")
        .unwrap_or_else(|_| "nexus-bootstrap-admin-secret-v1".to_string());

    loop {
        let Ok((socket, _)) = listener.accept().await else { break };
        let voter_c = voter.clone();
        let guard_c = guard.clone();
        let admin_tok = expected_admin_token.clone();
        tokio::spawn(async move {
            let (read_half, mut write_half) = socket.into_split();
            let mut reader = BufReader::new(read_half);
            let mut line = String::new();
            if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                return;
            }
            let resp = match serde_json::from_str::<VoterRpcReq>(line.trim()) {
                Ok(VoterRpcReq::Vote(vreq)) => match voter_c.cast_vote(&vreq).await {
                    Ok(vote) => VoterRpcResp::VoteOk { vote },
                    Err(e) => VoterRpcResp::Err { message: e.to_string() },
                },
                Ok(VoterRpcReq::PrepareTerm(preq)) => match voter_c.prepare_term(&preq).await {
                    Ok(promise) => VoterRpcResp::PromiseOk { promise },
                    Err(e) => VoterRpcResp::Err { message: e.to_string() },
                },
                Ok(VoterRpcReq::AdminProvisionGenesis {
                    admin_token,
                    group_id,
                    mode,
                    members,
                }) => {
                    if admin_token != admin_tok {
                        VoterRpcResp::Err {
                            message: "Unauthorized: invalid administrative bootstrap credential".into(),
                        }
                    } else {
                        match voter_c.install_genesis_epoch(&group_id, mode, members).await {
                            Ok(genesis_digest) => VoterRpcResp::GenesisProvisioned { genesis_digest },
                            Err(e) => VoterRpcResp::Err { message: e.to_string() },
                        }
                    }
                }
                Ok(VoterRpcReq::InstallMembershipEpoch { decision, prev_members }) => {
                    // NEVER call `install_genesis_epoch` from ordinary membership installation!
                    let prev_cfg = MembershipEpochConfig {
                        mode: decision.proposal.mode,
                        members: prev_members.into_iter().map(|m| (m.node_id.clone(), m)).collect(),
                    };
                    match voter_c.install_membership_epoch(&decision, &prev_cfg).await {
                        Ok(receipt) => VoterRpcResp::EpochInstalled { receipt },
                        Err(e) => VoterRpcResp::Err { message: e.to_string() },
                    }
                }
                Ok(VoterRpcReq::QueryLock { group_id, epoch, slot }) => {
                    match voter_c.query_slot_lock(&group_id, epoch, slot).await {
                        Ok(entry) => VoterRpcResp::LockFound { entry },
                        Err(e) => VoterRpcResp::Err { message: e.to_string() },
                    }
                }
                Ok(VoterRpcReq::InstallLeaseNow { lease, members }) => {
                    let grp = CoordinationGroup::new(lease.group_id.clone(), lease.qc.mode, members);
                    match guard_c.install_lease_now(&lease, &grp).await {
                        Ok(accepted_epoch) => VoterRpcResp::ExecOk { accepted_epoch },
                        Err(e) => VoterRpcResp::Err { message: e.to_string() },
                    }
                }
                Ok(VoterRpcReq::ExecLocalNow {
                    resource_key,
                    holder_node_id,
                    fencing_epoch,
                }) => match guard_c
                    .authorize_local_exec_now(&resource_key, &holder_node_id, fencing_epoch)
                    .await
                {
                    Ok(accepted_epoch) => VoterRpcResp::ExecOk { accepted_epoch },
                    Err(e) => VoterRpcResp::Err { message: e.to_string() },
                },
                Err(e) => VoterRpcResp::Err { message: e.to_string() },
            };
            let out = format!("{}\n", serde_json::to_string(&resp).unwrap());
            let _ = write_half.write_all(out.as_bytes()).await;
            let _ = write_half.flush().await;
        });
    }
}

async fn run_coordinator_child() {
    let data_dir = PathBuf::from(std::env::var("NEXUS_CHILD_DATA_DIR").unwrap());
    let members_json = std::env::var("NEXUS_CHILD_MEMBERS_JSON").unwrap();
    let members: Vec<GroupMember> = serde_json::from_str(&members_json).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    let db = Arc::new(Database::init_in(data_dir.join("db")).await);
    let group = CoordinationGroup::open_durable(db, "pool:mp", ConsensusMode::CftFastPath, members)
        .await
        .unwrap();
    let shared_group = Arc::new(Mutex::new(group));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    println!("READY {}", addr);
    use std::io::Write as _;
    std::io::stdout().flush().unwrap();

    loop {
        let Ok((socket, _)) = listener.accept().await else { break };
        let grp_arc = shared_group.clone();
        tokio::spawn(async move {
            let (read_half, mut write_half) = socket.into_split();
            let mut reader = BufReader::new(read_half);
            let mut line = String::new();
            if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                return;
            }
            let resp = match serde_json::from_str::<CoordRpcReq>(line.trim()) {
                Ok(CoordRpcReq::ProposeAndCommit {
                    voter_addrs,
                    lease_id,
                    resource_key,
                    holder_node_id,
                    workload_id,
                    issued_at_ms,
                    expires_at_ms,
                    now,
                    skip_persist,
                }) => {
                    let (gid, epoch, slot, next_fence) = {
                        let g = grp_arc.lock().await;
                        let nf = g.max_fencing_epoch.get(&resource_key).copied().unwrap_or(0) + 1;
                        (g.group_id.clone(), g.membership_epoch, g.next_slot, nf)
                    };
                    let proposal = LeaseProposal {
                        group_id: gid.clone(),
                        lease_id: lease_id.clone(),
                        resource_key: resource_key.clone(),
                        holder_node_id: holder_node_id.clone(),
                        workload_id: workload_id.clone(),
                        fencing_epoch: next_fence,
                        issued_at_ms,
                        expires_at_ms,
                    };
                    let prop_hash = proposal.canonical_digest();
                    let vreq = VoteRequest::for_lease(epoch, slot, proposal);
                    let votes = fan_out_votes_tcp(&voter_addrs, vreq).await;
                    if skip_persist {
                        CoordRpcResp::VotesCollectedOnly {
                            count: votes.len(),
                            proposal_hash: prop_hash,
                        }
                    } else {
                        let mut g = grp_arc.lock().await;
                        match g
                            .commit_exclusive_lease(
                                &lease_id,
                                &resource_key,
                                &holder_node_id,
                                &workload_id,
                                issued_at_ms,
                                expires_at_ms,
                                now,
                                votes,
                            )
                            .await
                        {
                            Ok(lease) => CoordRpcResp::Committed { lease },
                            Err(e) => CoordRpcResp::Err { message: e.to_string() },
                        }
                    }
                }
                Ok(CoordRpcReq::ProposeMembership {
                    voter_addrs,
                    new_members,
                    skip_persist,
                }) => {
                    let (gid, epoch, slot, mode) = {
                        let g = grp_arc.lock().await;
                        (g.group_id.clone(), g.membership_epoch, g.next_slot, g.mode)
                    };
                    let prop = match MembershipTransitionProposal::new(
                        gid,
                        epoch,
                        epoch + 1,
                        slot,
                        mode,
                        new_members,
                    ) {
                        Ok(p) => p,
                        Err(e) => {
                            let out = format!(
                                "{}\n",
                                serde_json::to_string(&CoordRpcResp::Err { message: e.to_string() }).unwrap()
                            );
                            let _ = write_half.write_all(out.as_bytes()).await;
                            let _ = write_half.flush().await;
                            return;
                        }
                    };
                    let prop_hash = prop.canonical_digest().unwrap();
                    let vreq = VoteRequest::for_membership(prop.clone()).unwrap();
                    let votes = fan_out_votes_tcp(&voter_addrs, vreq).await;
                    if skip_persist {
                        CoordRpcResp::VotesCollectedOnly {
                            count: votes.len(),
                            proposal_hash: prop_hash,
                        }
                    } else {
                        let mut g = grp_arc.lock().await;
                        match g.reconfigure_membership_with_quorum(&prop, votes).await {
                            Ok(decision) => CoordRpcResp::CommittedMembership { decision },
                            Err(e) => CoordRpcResp::Err { message: e.to_string() },
                        }
                    }
                }
                Ok(CoordRpcReq::RecoverAndCommitSlot { voter_addrs, slot }) => {
                    let (gid, epoch) = {
                        let g = grp_arc.lock().await;
                        (g.group_id.clone(), g.membership_epoch)
                    };
                    let mut entries = Vec::new();
                    for a in &voter_addrs {
                        if let VoterRpcResp::LockFound { entry: Some(pair) } = send_voter_rpc(
                            a,
                            &VoterRpcReq::QueryLock {
                                group_id: gid.clone(),
                                epoch,
                                slot,
                            },
                        )
                        .await
                        {
                            entries.push(pair);
                        }
                    }
                    let mut g = grp_arc.lock().await;
                    match g.recover_and_commit_slot(slot, entries).await {
                        Ok(Some(DurableSlotDecision::Lease(lease))) => CoordRpcResp::Committed { lease },
                        Ok(Some(DurableSlotDecision::Membership(decision))) => {
                            CoordRpcResp::CommittedMembership { decision }
                        }
                        Ok(Some(DurableSlotDecision::NoOp(_))) => CoordRpcResp::Ok,
                        Ok(None) => CoordRpcResp::Err { message: "No quorum found for slot".into() },
                        Err(e) => CoordRpcResp::Err { message: e.to_string() },
                    }
                }
                Ok(CoordRpcReq::GetState { resource_key }) => {
                    let g = grp_arc.lock().await;
                    CoordRpcResp::State {
                        membership_epoch: g.membership_epoch,
                        next_slot: g.next_slot,
                        lease: g.active_leases.get(&resource_key).cloned(),
                    }
                }
                Ok(CoordRpcReq::ExpireLocalLease { resource_key, now }) => {
                    let mut g = grp_arc.lock().await;
                    g.expire_lease_for_fault(&resource_key, now);
                    CoordRpcResp::Ok
                }
                Err(e) => CoordRpcResp::Err { message: e.to_string() },
            };
            let out = format!("{}\n", serde_json::to_string(&resp).unwrap());
            let _ = write_half.write_all(out.as_bytes()).await;
            let _ = write_half.flush().await;
        });
    }
}

fn spawn_voter(node_id: &str, data_dir: &PathBuf) -> (Child, String, String) {
    let exe = std::env::current_exe().unwrap();
    let mut child = Command::new(exe)
        .arg("--exact")
        .arg("five_process_autonomous_standby_recovery_and_host_clock_fencing")
        .arg("--nocapture")
        .env("NEXUS_CHILD_ROLE", "voter")
        .env("NEXUS_CHILD_NODE_ID", node_id)
        .env("NEXUS_CHILD_DATA_DIR", data_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn voter child process");

    let stdout = child.stdout.take().unwrap();
    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();
    use std::io::BufRead as _;
    loop {
        line.clear();
        let n = reader.read_line(&mut line).expect("read voter READY");
        assert!(n > 0, "Voter '{}' exited before READY", node_id);
        if let Some(rest) = line.trim().strip_prefix("READY ") {
            let mut parts = rest.split_whitespace();
            return (child, parts.next().unwrap().into(), parts.next().unwrap().into());
        }
    }
}

fn spawn_coordinator(data_dir: &PathBuf, members: &[GroupMember]) -> (Child, String) {
    let exe = std::env::current_exe().unwrap();
    let mut child = Command::new(exe)
        .arg("--exact")
        .arg("five_process_autonomous_standby_recovery_and_host_clock_fencing")
        .arg("--nocapture")
        .env("NEXUS_CHILD_ROLE", "coordinator")
        .env("NEXUS_CHILD_DATA_DIR", data_dir)
        .env("NEXUS_CHILD_MEMBERS_JSON", serde_json::to_string(members).unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn coordinator child process");

    let stdout = child.stdout.take().unwrap();
    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();
    use std::io::BufRead as _;
    loop {
        line.clear();
        let n = reader.read_line(&mut line).expect("read coordinator READY");
        assert!(n > 0, "Coordinator exited before READY");
        if let Some(addr) = line.trim().strip_prefix("READY ") {
            return (child, addr.to_string());
        }
    }
}

#[tokio::test]
async fn five_process_autonomous_standby_recovery_and_host_clock_fencing() {
    match std::env::var("NEXUS_CHILD_ROLE").ok().as_deref() {
        Some("voter") => {
            run_voter_child().await;
            return;
        }
        Some("coordinator") => {
            run_coordinator_child().await;
            return;
        }
        _ => {}
    }

    let base_dir = std::env::temp_dir().join(format!("nexus_5proc_auto_{}", uuid::Uuid::new_v4().simple()));
    let (mut v1, v_addr1, pk1) = spawn_voter("node-1", &base_dir.join("v1"));
    let (mut v2, v_addr2, pk2) = spawn_voter("node-2", &base_dir.join("v2"));
    let (mut v3, v_addr3, pk3) = spawn_voter("node-3", &base_dir.join("v3"));
    let all_voters = vec![v_addr1.clone(), v_addr2.clone(), v_addr3.clone()];

    let members = vec![
        GroupMember { node_id: "node-1".into(), identity_id: "nxid_1".into(), org_id: "org_mp".into(), ed25519_pubkey: pk1 },
        GroupMember { node_id: "node-2".into(), identity_id: "nxid_2".into(), org_id: "org_mp".into(), ed25519_pubkey: pk2 },
        GroupMember { node_id: "node-3".into(), identity_id: "nxid_3".into(), org_id: "org_mp".into(), ed25519_pubkey: pk3 },
    ];

    let c1_dir = base_dir.join("coord-1");
    let c2_dir = base_dir.join("coord-2");
    let (c1, c_addr1) = spawn_coordinator(&c1_dir, &members);
    let (c2, c_addr2) = spawn_coordinator(&c2_dir, &members);

    // Use real wall-clock time so resource host's `install_lease_now()` / `authorize_local_exec_now()` validates cleanly!
    let now = CoordinationGroup::now_ms();

    // 1. Two independent coordinator processes race slot 1 concurrently
    let race_1 = CoordRpcReq::ProposeAndCommit {
        voter_addrs: all_voters.clone(),
        lease_id: "lse_c1_s1".into(),
        resource_key: "gpu:mp:0".into(),
        holder_node_id: "node-1".into(),
        workload_id: "wl-c1".into(),
        issued_at_ms: now,
        expires_at_ms: now + 120_000,
        now,
        skip_persist: false,
    };
    let race_2 = CoordRpcReq::ProposeAndCommit {
        voter_addrs: all_voters.clone(),
        lease_id: "lse_c2_s1".into(),
        resource_key: "gpu:mp:0".into(),
        holder_node_id: "node-2".into(),
        workload_id: "wl-c2".into(),
        issued_at_ms: now,
        expires_at_ms: now + 120_000,
        now,
        skip_persist: false,
    };
    let (r1, r2) = tokio::join!(
        send_coord_rpc(&c_addr1, &race_1),
        send_coord_rpc(&c_addr2, &race_2),
    );
    let (slot1_lease, winner_is_c1) = match (r1, r2) {
        (CoordRpcResp::Committed { lease }, CoordRpcResp::Err { .. }) => (lease, true),
        (CoordRpcResp::Err { .. }, CoordRpcResp::Committed { lease }) => (lease, false),
        (CoordRpcResp::Committed { .. }, CoordRpcResp::Committed { .. }) => {
            panic!("SAFETY VIOLATION: Both coordinator processes committed on slot 1!");
        }
        other => panic!("Expected exactly one coordinator to commit on slot 1, got {:?}", other),
    };
    assert_eq!(slot1_lease.fencing_epoch, 1);

    let (mut active_coord, active_addr, mut standby_coord, standby_addr, standby_dir) = if winner_is_c1 {
        (c1, c_addr1, c2, c_addr2, c2_dir)
    } else {
        (c2, c_addr2, c1, c_addr1, c1_dir)
    };

    // 2. DECISIVE AUTONOMOUS RECOVERY TEST:
    //    Active coordinator gathers quorum (2 of 3) on slot 2 with `skip_persist = true`, then is
    //    KILLED PERMANENTLY (NEVER restarted, NEVER resubmits!).
    let _ = send_coord_rpc(
        &active_addr,
        &CoordRpcReq::ExpireLocalLease {
            resource_key: "gpu:mp:0".into(),
            now: now + 130_000,
        },
    )
    .await;
    let pre_crash = send_coord_rpc(
        &active_addr,
        &CoordRpcReq::ProposeAndCommit {
            voter_addrs: vec![v_addr2.clone(), v_addr3.clone()], // 2 of 3 = quorum!
            lease_id: "lse_autonomous_s2".into(),
            resource_key: "gpu:mp:0".into(),
            holder_node_id: "node-2".into(),
            workload_id: "wl-autonomous".into(),
            issued_at_ms: now,
            expires_at_ms: now + 180_000,
            now,
            skip_persist: true,
        },
    )
    .await;
    let expected_s2_hash = match pre_crash {
        CoordRpcResp::VotesCollectedOnly { count: 2, proposal_hash } => proposal_hash,
        other => panic!("Expected 2 votes before permanent coordinator kill, got {:?}", other),
    };
    // KILL active coordinator PERMANENTLY!
    let _ = active_coord.kill();
    let _ = active_coord.wait();

    // Standby coordinator autonomously queries all 3 voters, reconstructs BOTH proposal & QC,
    // and COMMITS the exact lease to its own durable `redb` database!
    let recovered_lease = match send_coord_rpc(
        &standby_addr,
        &CoordRpcReq::RecoverAndCommitSlot {
            voter_addrs: all_voters.clone(),
            slot: 2,
        },
    )
    .await
    {
        CoordRpcResp::Committed { lease } => lease,
        other => panic!("Standby coordinator failed autonomous recover-and-commit on slot 2: {:?}", other),
    };
    assert_eq!(recovered_lease.canonical_digest(), expected_s2_hash);
    assert_eq!(recovered_lease.fencing_epoch, 2);
    assert_eq!(recovered_lease.lease_id, "lse_autonomous_s2");

    // 3. KILL & RESTART standby coordinator from its on-disk DB -> verify decision & next_slot==3 survive!
    let _ = standby_coord.kill();
    let _ = standby_coord.wait();
    let (mut standby_restarted, standby_addr_2) = spawn_coordinator(&standby_dir, &members);
    let (persisted_next_slot, persisted_lease) = match send_coord_rpc(
        &standby_addr_2,
        &CoordRpcReq::GetState {
            resource_key: "gpu:mp:0".into(),
        },
    )
    .await
    {
        CoordRpcResp::State { next_slot, lease: Some(l), .. } => (next_slot, l),
        other => panic!("Restarted standby coordinator lost recovered state: {:?}", other),
    };
    assert_eq!(persisted_next_slot, 3);
    assert_eq!(persisted_lease.canonical_digest(), expected_s2_hash);

    // 4. Install exact recovered lease on node-3 using HOST-TRUSTED CLOCK (`install_lease_now`)!
    assert!(matches!(
        send_voter_rpc(
            &v_addr3,
            &VoterRpcReq::InstallLeaseNow {
                lease: persisted_lease.clone(),
                members: members.clone(),
            },
        )
        .await,
        VoterRpcResp::ExecOk { accepted_epoch: 2 }
    ));

    // Exact retry -> strictly idempotent OK
    assert!(matches!(
        send_voter_rpc(
            &v_addr3,
            &VoterRpcReq::InstallLeaseNow {
                lease: persisted_lease.clone(),
                members: members.clone(),
            },
        )
        .await,
        VoterRpcResp::ExecOk { accepted_epoch: 2 }
    ));

    // +1 ms expiry tampering -> REJECTED!
    let mut tampered = persisted_lease.clone();
    tampered.expires_at_ms += 1;
    assert!(matches!(
        send_voter_rpc(
            &v_addr3,
            &VoterRpcReq::InstallLeaseNow {
                lease: tampered,
                members: members.clone(),
            },
        )
        .await,
        VoterRpcResp::Err { .. }
    ));

    // Stale epoch=1 lease installation & execution -> REJECTED!
    assert!(matches!(
        send_voter_rpc(
            &v_addr3,
            &VoterRpcReq::InstallLeaseNow {
                lease: slot1_lease.clone(),
                members: members.clone(),
            },
        )
        .await,
        VoterRpcResp::Err { .. }
    ));
    assert!(matches!(
        send_voter_rpc(
            &v_addr3,
            &VoterRpcReq::ExecLocalNow {
                resource_key: "gpu:mp:0".into(),
                holder_node_id: slot1_lease.holder_node_id.clone(),
                fencing_epoch: 1,
            },
        )
        .await,
        VoterRpcResp::Err { .. }
    ));

    // Hot-path execution for recovered epoch=2 -> ACCEPTED!
    assert!(matches!(
        send_voter_rpc(
            &v_addr3,
            &VoterRpcReq::ExecLocalNow {
                resource_key: "gpu:mp:0".into(),
                holder_node_id: "node-2".into(),
                fencing_epoch: 2,
            },
        )
        .await,
        VoterRpcResp::ExecOk { accepted_epoch: 2 }
    ));

    // 5. Milestone 1: Standby autonomous recovery of a MEMBERSHIP TRANSITION on slot 3!
    //    `standby_restarted` collects quorum (2 of 3) on `SlotProposal::Membership` (epoch 1 -> 2,
    //    dropping node-3) with `skip_persist = true`, then is KILLED PERMANENTLY!
    let epoch2_members = vec![members[0].clone(), members[1].clone()];
    let mem_pre_crash = send_coord_rpc(
        &standby_addr_2,
        &CoordRpcReq::ProposeMembership {
            voter_addrs: vec![v_addr1.clone(), v_addr2.clone()],
            new_members: epoch2_members.clone(),
            skip_persist: true,
        },
    )
    .await;
    let expected_m_hash = match mem_pre_crash {
        CoordRpcResp::VotesCollectedOnly { count: 2, proposal_hash } => proposal_hash,
        other => panic!("Expected 2 membership votes before coordinator kill, got {:?}", other),
    };
    // KILL `standby_restarted` PERMANENTLY!
    let _ = standby_restarted.kill();
    let _ = standby_restarted.wait();

    // Fresh standby coordinator (`coord-3`) queries the 3 voter processes, recovers & commits
    // `DurableSlotDecision::Membership` for slot 3 WITHOUT the original coordinator!
    let coord3_dir = base_dir.join("coord-3");
    let (mut coord3, coord3_addr) = spawn_coordinator(&coord3_dir, &members);
    let recovered_mdec = match send_coord_rpc(
        &coord3_addr,
        &CoordRpcReq::RecoverAndCommitSlot {
            voter_addrs: all_voters.clone(),
            slot: 3,
        },
    )
    .await
    {
        CoordRpcResp::CommittedMembership { decision } => decision,
        other => panic!("Standby coord-3 failed autonomous membership recovery on slot 3: {:?}", other),
    };
    assert_eq!(recovered_mdec.canonical_digest().unwrap(), expected_m_hash);
    assert_eq!(recovered_mdec.proposal.next_epoch, 2);

    // Kill & restart `coord-3` from its on-disk DB -> verified epoch chain 1 -> 2 survives restart!
    let _ = coord3.kill();
    let _ = coord3.wait();
    let (mut coord3_restarted, coord3_addr_2) = spawn_coordinator(&coord3_dir, &members);
    match send_coord_rpc(
        &coord3_addr_2,
        &CoordRpcReq::GetState {
            resource_key: "gpu:mp:0".into(),
        },
    )
    .await
    {
        CoordRpcResp::State {
            membership_epoch: 2,
            next_slot: 4,
            ..
        } => {}
        other => panic!("Restarted coord-3 failed to reconstruct verified epoch 2 chain: {:?}", other),
    }

    // 6. Milestone 2 & 2.2.1: Authenticated genesis provisioning, full EpochInstallReceipt over TCP,
    //    removed-member fencing, same-term leader conflict rejection, and stale-term fencing!
    let admin_token = "nexus-bootstrap-admin-secret-v1".to_string();
    // Unauthenticated genesis provisioning MUST be rejected!
    assert!(matches!(
        send_voter_rpc(
            &v_addr1,
            &VoterRpcReq::AdminProvisionGenesis {
                admin_token: "WRONG_TOKEN".into(),
                group_id: "pool:mp".into(),
                mode: ConsensusMode::CftFastPath,
                members: members.clone(),
            },
        )
        .await,
        VoterRpcResp::Err { .. }
    ));
    // Unprovisioned voter MUST reject `InstallMembershipEpoch` (cannot establish its own anchor!)
    assert!(matches!(
        send_voter_rpc(
            &v_addr1,
            &VoterRpcReq::InstallMembershipEpoch {
                decision: recovered_mdec.clone(),
                prev_members: members.clone(),
            },
        )
        .await,
        VoterRpcResp::Err { .. }
    ));

    // Explicitly provision trusted genesis on v1, v2, v3 with authenticated admin credential
    // (idempotent on exact repeat; rejects conflicting replacement!)
    for addr in [&v_addr1, &v_addr2, &v_addr3] {
        assert!(matches!(
            send_voter_rpc(
                addr,
                &VoterRpcReq::AdminProvisionGenesis {
                    admin_token: admin_token.clone(),
                    group_id: "pool:mp".into(),
                    mode: ConsensusMode::CftFastPath,
                    members: members.clone(),
                },
            )
            .await,
            VoterRpcResp::GenesisProvisioned { .. }
        ));
    }
    assert!(matches!(
        send_voter_rpc(
            &v_addr1,
            &VoterRpcReq::AdminProvisionGenesis {
                admin_token: admin_token.clone(),
                group_id: "pool:mp".into(),
                mode: ConsensusMode::CftFastPath,
                members: epoch2_members.clone(), // Conflicting genesis replacement!
            },
        )
        .await,
        VoterRpcResp::Err { .. }
    ));

    // Install epoch 2 on v1, v2, v3 over TCP -> collect FULL EpochInstallReceipts & verify via shared verifier!
    let mut tcp_receipts = Vec::new();
    for addr in [&v_addr1, &v_addr2, &v_addr3] {
        match send_voter_rpc(
            addr,
            &VoterRpcReq::InstallMembershipEpoch {
                decision: recovered_mdec.clone(),
                prev_members: members.clone(),
            },
        )
        .await
        {
            VoterRpcResp::EpochInstalled { receipt } => {
                assert_eq!(receipt.min_active_epoch, 2);
                assert_eq!(receipt.barrier_slot, 3);
                assert!(receipt.post_transition_old_locks.is_empty());
                tcp_receipts.push(receipt);
            }
            other => panic!("Expected full EpochInstallReceipt over TCP, got {:?}", other),
        }
    }
    let mp_verifier = CoordinationGroup::new("pool:mp", ConsensusMode::CftFastPath, members.clone());
    let mp_prev_cfg = MembershipEpochConfig {
        mode: ConsensusMode::CftFastPath,
        members: members.iter().cloned().map(|m| (m.node_id.clone(), m)).collect(),
    };
    let pending = mp_verifier
        .verify_activation_receipts(&recovered_mdec, &mp_prev_cfg, &tcp_receipts)
        .unwrap();
    assert!(pending.is_empty());
    // Duplicate receipt MUST be rejected by shared verifier!
    let dup_receipts = vec![tcp_receipts[0].clone(), tcp_receipts[0].clone()];
    assert!(mp_verifier
        .verify_activation_receipts(&recovered_mdec, &mp_prev_cfg, &dup_receipts)
        .is_err());

    // 7. Milestone 2.2.1: Remote unresolved S+1 lock over TCP blocks activation EVEN WHEN
    //    remaining voters (v1, v2) satisfy BOTH old (2/3) and new (2/2) quorum counts!
    for addr in [&v_addr1, &v_addr2, &v_addr3] {
        assert!(matches!(
            send_voter_rpc(
                addr,
                &VoterRpcReq::AdminProvisionGenesis {
                    admin_token: admin_token.clone(),
                    group_id: "pool:mp-unres".into(),
                    mode: ConsensusMode::CftFastPath,
                    members: members.clone(),
                },
            )
            .await,
            VoterRpcResp::GenesisProvisioned { .. }
        ));
    }
    let mut unres_promises = Vec::new();
    let unres_prep = PrepareTermRequest {
        group_id: "pool:mp-unres".into(),
        epoch: 1,
        term: 1,
        leader_id: "coord-unres".into(),
        from_slot: 1,
    };
    for addr in [&v_addr1, &v_addr2, &v_addr3] {
        match send_voter_rpc(addr, &VoterRpcReq::PrepareTerm(unres_prep.clone())).await {
            VoterRpcResp::PromiseOk { promise } => unres_promises.push(promise),
            other => panic!("Expected PromiseOk on pool:mp-unres, got {:?}", other),
        }
    }
    let unres_cert = TermCertificate {
        group_id: "pool:mp-unres".into(),
        epoch: 1,
        term: 1,
        leader_id: "coord-unres".into(),
        from_slot: 1,
        mode: ConsensusMode::CftFastPath,
        promises: unres_promises,
    };
    let unres_mprop = MembershipTransitionProposal::new(
        "pool:mp-unres",
        1,
        2,
        1,
        ConsensusMode::CftFastPath,
        epoch2_members.clone(),
    )
    .unwrap();
    let unres_mreq = VoteRequest::for_membership(unres_mprop.clone())
        .unwrap()
        .with_term(1, "coord-unres", unres_cert.clone());
    let mut unres_mvotes = Vec::new();
    for addr in [&v_addr1, &v_addr2] {
        match send_voter_rpc(addr, &VoterRpcReq::Vote(unres_mreq.clone())).await {
            VoterRpcResp::VoteOk { vote } => unres_mvotes.push(vote),
            other => panic!("Expected VoteOk for membership transition, got {:?}", other),
        }
    }
    let mut unres_grp =
        CoordinationGroup::new("pool:mp-unres", ConsensusMode::CftFastPath, members.clone());
    let unres_mdec = unres_grp
        .reconfigure_membership_with_quorum(&unres_mprop, unres_mvotes)
        .await
        .unwrap();
    // Meanwhile remote voter v3 accepts an old-epoch S+1 lease at slot 2!
    let unres_s2_lp = LeaseProposal {
        group_id: "pool:mp-unres".into(),
        lease_id: "lse_remote_unres_s2".into(),
        resource_key: "gpu:unres:0".into(),
        holder_node_id: "node-3".into(),
        workload_id: "wl-unres".into(),
        fencing_epoch: 1,
        issued_at_ms: now,
        expires_at_ms: now + 60_000,
    };
    let unres_s2_req =
        VoteRequest::for_lease(1, 2, unres_s2_lp).with_term(1, "coord-unres", unres_cert);
    assert!(matches!(
        send_voter_rpc(&v_addr3, &VoterRpcReq::Vote(unres_s2_req)).await,
        VoterRpcResp::VoteOk { .. }
    ));
    // Install transition on all 3 remote TCP voters -> collect full receipts!
    let mut unres_receipts = Vec::new();
    for addr in [&v_addr1, &v_addr2, &v_addr3] {
        match send_voter_rpc(
            addr,
            &VoterRpcReq::InstallMembershipEpoch {
                decision: unres_mdec.clone(),
                prev_members: members.clone(),
            },
        )
        .await
        {
            VoterRpcResp::EpochInstalled { receipt } => unres_receipts.push(receipt),
            other => panic!("Expected EpochInstalled receipt, got {:?}", other),
        }
    }
    assert_eq!(unres_receipts[2].min_active_epoch, 1);
    assert_eq!(unres_receipts[2].post_transition_old_locks.len(), 1);
    assert_eq!(unres_receipts[2].post_transition_old_locks[0].slot, 2);
    // Remote activation MUST FAIL CLOSED even though v1 & v2 satisfy both quorum counts!
    assert!(
        unres_grp
            .verify_activation_receipts(&unres_mdec, &mp_prev_cfg, &unres_receipts)
            .is_err(),
        "Remote unresolved S+1 lock in EpochInstallReceipt MUST block activation over TCP!"
    );

    // Removed member `node-3` MUST reject BOTH stale epoch 1 AND new epoch 2 over TCP!
    let stale_e1_prep = PrepareTermRequest {
        group_id: "pool:mp".into(),
        epoch: 1,
        term: 1,
        leader_id: "old-coord".into(),
        from_slot: 1,
    };
    assert!(matches!(
        send_voter_rpc(&v_addr3, &VoterRpcReq::PrepareTerm(stale_e1_prep.clone())).await,
        VoterRpcResp::Err { .. }
    ));
    let e2_t1_prep = PrepareTermRequest {
        group_id: "pool:mp".into(),
        epoch: 2,
        term: 1,
        leader_id: "coord-3".into(),
        from_slot: 4,
    };
    assert!(matches!(
        send_voter_rpc(&v_addr3, &VoterRpcReq::PrepareTerm(e2_t1_prep.clone())).await,
        VoterRpcResp::Err { .. }
    ));

    // Active epoch-2 voters (`v1`, `v2`) promise term 1 to `coord-3`, reject rival leader in term 1,
    // and once term 2 is promised to `coord-4`, fence reconnecting `coord-3` (term 1)!
    assert!(matches!(
        send_voter_rpc(&v_addr1, &VoterRpcReq::PrepareTerm(e2_t1_prep.clone())).await,
        VoterRpcResp::PromiseOk { .. }
    ));
    assert!(matches!(
        send_voter_rpc(&v_addr2, &VoterRpcReq::PrepareTerm(e2_t1_prep.clone())).await,
        VoterRpcResp::PromiseOk { .. }
    ));
    let rival_t1_prep = PrepareTermRequest {
        leader_id: "coord-rival".into(),
        ..e2_t1_prep.clone()
    };
    assert!(matches!(
        send_voter_rpc(&v_addr1, &VoterRpcReq::PrepareTerm(rival_t1_prep)).await,
        VoterRpcResp::Err { .. }
    ));
    let e2_t2_prep = PrepareTermRequest {
        term: 2,
        leader_id: "coord-4".into(),
        ..e2_t1_prep.clone()
    };
    assert!(matches!(
        send_voter_rpc(&v_addr1, &VoterRpcReq::PrepareTerm(e2_t2_prep.clone())).await,
        VoterRpcResp::PromiseOk { .. }
    ));
    assert!(matches!(
        send_voter_rpc(&v_addr2, &VoterRpcReq::PrepareTerm(e2_t2_prep)).await,
        VoterRpcResp::PromiseOk { .. }
    ));
    // Reconnecting stale term-1 `coord-3` is rejected by independent TCP voters!
    assert!(matches!(
        send_voter_rpc(&v_addr1, &VoterRpcReq::PrepareTerm(e2_t1_prep)).await,
        VoterRpcResp::Err { .. }
    ));
    // And stale epoch-1 request is rejected by active epoch-2 voter `v1`!
    assert!(matches!(
        send_voter_rpc(&v_addr1, &VoterRpcReq::PrepareTerm(stale_e1_prep)).await,
        VoterRpcResp::Err { .. }
    ));

    let _ = coord3_restarted.kill();
    let _ = coord3_restarted.wait();
    let _ = v1.kill();
    let _ = v1.wait();
    let _ = v2.kill();
    let _ = v2.wait();
    let _ = v3.kill();
    let _ = v3.wait();
    let _ = std::fs::remove_dir_all(&base_dir);
}
