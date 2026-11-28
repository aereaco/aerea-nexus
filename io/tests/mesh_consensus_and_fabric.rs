//! Final Acceptance Gate Regression Suite (Resource Trust, Lease Binding, Legacy/Conflict Fail-Closed)

use nexus_io::db::{is_already_exists_error, Database};
use nexus_io::iam::idp::{NexusIdp, OrgPolicyPatch};
use nexus_io::mesh::consensus::{
    hash_genesis_config, hash_lease_proposal, hash_membership_change, sign_vote_raw,
    sign_vote_raw_in_term, verify_term_certificate_and_adoption, AcceptedSlotLock, ConsensusMode,
    CoordinationGroup, FencedLease, FencedResourceGuard, GenesisAnchorError, GroupMember,
    LeaseProposal, MembershipEpochConfig, MembershipTransitionProposal, PrepareTermRequest,
    QuorumCertificate, SlotProposal, TermCertificate, VoteRequest, VoterNode,
};
use nexus_io::mesh::resources::{
    schedule_and_lease_workload, GpuCapability, NodeAdvertisement, ReservationLedger,
    ResourceMeshCrdt, WorkloadSpec,
};
use nexus_io::storage::blob_bridge::BlobBridge;
use nexus_io::storage::cas_store::CasStore;
use std::sync::Arc;

#[tokio::test]
async fn p0_resource_trust_crdt_expiry_membership_digest_and_authenticated_boundary_fencing() {
    let db_coord = Arc::new(Database::open_mem());
    let idp = NexusIdp::new(db_coord.clone());
    let org = idp
        .create_org("root", "nexus-mesh", "Nexus Mesh Org", None, None, OrgPolicyPatch::default())
        .await
        .unwrap();

    let (id_a, sk_a) = idp.create_identity("node-a-control", None).await.unwrap();
    let (id_b, sk_b) = idp.create_identity("node-b-cpu", None).await.unwrap();
    let (id_c, sk_c) = idp.create_identity("node-c-gpu", None).await.unwrap();
    let (id_d, sk_d) = idp.create_identity("node-d-storage", None).await.unwrap();

    let members = vec![
        GroupMember { node_id: "node-a".into(), identity_id: id_a.identity_id.clone(), org_id: org.org_id.clone(), ed25519_pubkey: id_a.active_pubkey.clone() },
        GroupMember { node_id: "node-b".into(), identity_id: id_b.identity_id.clone(), org_id: org.org_id.clone(), ed25519_pubkey: id_b.active_pubkey.clone() },
        GroupMember { node_id: "node-c".into(), identity_id: id_c.identity_id.clone(), org_id: org.org_id.clone(), ed25519_pubkey: id_c.active_pubkey.clone() },
        GroupMember { node_id: "node-d".into(), identity_id: id_d.identity_id.clone(), org_id: org.org_id.clone(), ed25519_pubkey: id_d.active_pubkey.clone() },
    ];

    let voter_a = VoterNode::new("node-a", sk_a.clone(), Arc::new(Database::open_mem())).with_legacy_term_zero_compat();
    let voter_b = VoterNode::new("node-b", sk_b.clone(), Arc::new(Database::open_mem())).with_legacy_term_zero_compat();
    let voter_c = VoterNode::new("node-c", sk_c.clone(), Arc::new(Database::open_mem())).with_legacy_term_zero_compat();
    let voter_d = VoterNode::new("node-d", sk_d.clone(), Arc::new(Database::open_mem())).with_legacy_term_zero_compat();
    let all_voters = vec![voter_a.clone(), voter_b.clone(), voter_c.clone(), voter_d.clone()];

    let mut group = CoordinationGroup::open_durable(
        db_coord.clone(),
        "pool:us-east",
        ConsensusMode::CftFastPath,
        members.clone(),
    )
    .await
    .unwrap();

    let tmp_dir = std::env::temp_dir().join(format!("nexus_mesh_p0_{}", uuid::Uuid::new_v4().simple()));
    let blobs = Arc::new(BlobBridge::new_in(db_coord.clone(), tmp_dir.clone()).await.unwrap());
    let cas = CasStore::new(blobs);
    let dataset = serde_json::json!({ "shard": "alpha-v1", "weights_digest": "blake3:verified" });
    let cid = cas.commit_manifest_cas("mesh-datasets", "alpha-v1.json", &dataset, None).await.unwrap();

    let t0 = CoordinationGroup::now_ms();
    let exp = t0 + 120_000;

    let mut adv_c = NodeAdvertisement {
        node_id: "node-c".into(),
        identity_id: id_c.identity_id.clone(),
        org_id: org.org_id.clone(),
        group_id: "pool:us-east".into(),
        region: "us-east".into(),
        ed25519_pubkey: id_c.active_pubkey.clone(),
        cpu_arch: "x86_64".into(),
        cpu_cores: 16,
        available_cpu_cores: 12,
        ram_mb: 65_536,
        available_ram_mb: 48_000,
        shared_arena_mb: 8192,
        cas_storage_gb: 500,
        verified_local_cas_cids: vec![cid.clone()],
        advertised_cas_cids: vec![],
        gpus: vec![GpuCapability {
            vendor: "NVIDIA".into(),
            model: "RTX 4090".into(),
            vram_mb: 24_576,
            free_vram_mb: 22_000,
            apis: vec!["cuda".into(), "vulkan".into()],
        }],
        wasm_slots: 4,
        healthy: true,
        tombstone: false,
        expires_at_ms: exp,
        lamport_ts: 1,
        signature: String::new(),
    };
    adv_c.sign(&sk_c).unwrap();

    let mut crdt_a = ResourceMeshCrdt::new();
    let mut tampered_gpu = adv_c.clone();
    tampered_gpu.gpus[0].apis.push("rocm".into());
    assert!(crdt_a.merge_advertisement(tampered_gpu, &group, t0).is_err());

    let mut expired_adv = adv_c.clone();
    expired_adv.expires_at_ms = t0 - 1;
    expired_adv.sign(&sk_c).unwrap();
    assert!(crdt_a.merge_advertisement(expired_adv, &group, t0).is_err());

    crdt_a.merge_advertisement(adv_c.clone(), &group, t0).unwrap();

    // 1. Place workload -> durable voter locks include canonical LeaseProposal
    let mut reservations = ReservationLedger::new();
    let gpu_spec = WorkloadSpec {
        workload_id: "wl-gpu-1".into(),
        required_org_id: org.org_id.clone(),
        min_cpu_cores: 4,
        min_ram_mb: 16_000,
        min_gpu_vram_mb: 16_000,
        required_gpu_api: Some("cuda".into()),
        required_wasm_slots: 3,
        preferred_region: Some("us-east".into()),
        input_cas_cid: Some(cid.clone()),
        require_verified_cas_locality: true,
    };
    let dec1 = schedule_and_lease_workload(
        &crdt_a,
        &mut reservations,
        &mut group,
        &gpu_spec,
        "gpu:us-east:slot-0",
        60_000,
        t0,
        &all_voters,
    )
    .await
    .unwrap();
    assert_eq!(dec1.selected_node_id, "node-c");

    // 2. Host-trusted clock (`install_lease_now` / `authorize_local_exec_now`) + +1ms expiry tamper!
    let guard = FencedResourceGuard::new(Arc::new(Database::open_mem()));
    guard.install_lease_now(&dec1.lease, &group).await.unwrap();
    guard.install_lease_now(&dec1.lease, &group).await.unwrap(); // Strict idempotency
    guard.authorize_local_exec_now("gpu:us-east:slot-0", "node-c", 1).await.unwrap();

    let mut tampered_expiry = dec1.lease.clone();
    tampered_expiry.expires_at_ms += 1;
    assert!(guard.install_lease_now(&tampered_expiry, &group).await.is_err());

    // 3. Mismatched proposal payload rejected by VoterNode::cast_vote BEFORE locking!
    let bad_prop = LeaseProposal {
        group_id: "pool:us-east".into(),
        lease_id: "lse_bad".into(),
        resource_key: "gpu:us-east:slot-9".into(),
        holder_node_id: "node-b".into(),
        workload_id: "wl-bad".into(),
        fencing_epoch: 1,
        issued_at_ms: t0,
        expires_at_ms: t0 + 30_000,
    };
    let tampered_vote_req = VoteRequest {
        group_id: "pool:us-east".into(),
        epoch: 1,
        slot: 50,
        proposal_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
        proposal: Some(SlotProposal::Lease(bad_prop)),
        term: 0,
        leader_id: None,
        term_cert: None,
    };
    assert!(
        voter_a.cast_vote(&tampered_vote_req).await.is_err(),
        "Voter MUST reject VoteRequest when proposal payload does not match proposal_hash!"
    );

    // 4. Production vote API MUST reject proposal-less VoteRequest; legacy on-disk lock MUST NOT
    //    be upgraded via idempotent retry and MUST fail closed on autonomous recovery!
    let legacy_prop = LeaseProposal {
        group_id: "pool:us-east".into(),
        lease_id: "lse_leg".into(),
        resource_key: "gpu:legacy".into(),
        holder_node_id: "node-b".into(),
        workload_id: "wl-leg".into(),
        fencing_epoch: 1,
        issued_at_ms: t0,
        expires_at_ms: t0 + 30_000,
    };
    let legacy_hash = legacy_prop.canonical_digest();
    let prod_none_req = VoteRequest {
        group_id: "pool:us-east".into(),
        epoch: 1,
        slot: 60,
        proposal_hash: legacy_hash.clone(),
        proposal: None,
        term: 0,
        leader_id: None,
        term_cert: None,
    };
    assert!(
        voter_a.cast_vote(&prod_none_req).await.is_err(),
        "Production VoterNode::cast_vote MUST reject proposal: None!"
    );

    // Seed pre-existing legacy on-disk lock (missing `proposal`) directly into voter DB
    let legacy_db = Arc::new(Database::open_mem());
    let legacy_voter = VoterNode::new("node-a", sk_a.clone(), legacy_db.clone()).with_legacy_term_zero_compat();
    legacy_voter.ensure_tables().await.unwrap();
    let lv1 = sign_vote_raw("pool:us-east", 1, 60, &legacy_hash, "node-a", &sk_a).unwrap();
    let lv2 = sign_vote_raw("pool:us-east", 1, 60, &legacy_hash, "node-b", &sk_b).unwrap();
    let lv3 = sign_vote_raw("pool:us-east", 1, 60, &legacy_hash, "node-c", &sk_c).unwrap();
    let legacy_lock_key = legacy_voter.slot_lock_key("pool:us-east", 1, 60);
    legacy_db
        .client
        .query("CREATE type::record('sys_mesh_voter_lock', $id) CONTENT $l;")
        .bind(("id", legacy_lock_key.clone()))
        .bind((
            "l",
            serde_json::json!({
                "lock_key": legacy_lock_key,
                "group_id": "pool:us-east",
                "epoch": 1,
                "slot": 60,
                "proposal_hash": legacy_hash,
                "voter_node_id": "node-a",
                "signature": lv1.signature,
                "locked_at_ms": t0,
            }),
        ))
        .await
        .unwrap();
    // Retry with matching hash + Some(proposal) MUST be rejected and MUST NOT upgrade the legacy lock!
    let upgrade_retry = VoteRequest {
        group_id: "pool:us-east".into(),
        epoch: 1,
        slot: 60,
        proposal_hash: legacy_hash.clone(),
        proposal: Some(SlotProposal::Lease(legacy_prop)),
        term: 0,
        leader_id: None,
        term_cert: None,
    };
    assert!(
        legacy_voter.cast_vote(&upgrade_retry).await.is_err(),
        "Legacy lock with proposal: None MUST NOT be upgraded or accepted on retry!"
    );
    let (_, still_none) = legacy_voter
        .query_slot_lock("pool:us-east", 1, 60)
        .await
        .unwrap()
        .unwrap();
    assert!(still_none.is_none(), "Legacy lock must remain unmodified on rejected retry");

    let mut rec_group = CoordinationGroup::new("pool:us-east", ConsensusMode::CftFastPath, members.clone());
    assert!(
        rec_group
            .recover_and_commit_slot(60, vec![(lv1, None), (lv2, None), (lv3, None)])
            .await
            .is_err(),
        "Autonomous recovery MUST fail closed when legacy voter locks lack LeaseProposal!"
    );

    // 5. Invalid/forged AND malformed durable decisions MUST fail closed on boot AND recovery!
    let forged_db = Arc::new(Database::open_mem());
    let mut forged_grp = CoordinationGroup::open_durable(
        forged_db.clone(),
        "pool:forged",
        ConsensusMode::CftFastPath,
        members.clone(),
    )
    .await
    .unwrap();
    let forged_lease = FencedLease {
        lease_id: "lse_forged".into(),
        group_id: "pool:forged".into(),
        resource_key: "r1".into(),
        holder_node_id: "node-a".into(),
        workload_id: "w1".into(),
        fencing_epoch: 1,
        issued_at_ms: t0,
        expires_at_ms: t0 + 30_000,
        qc: QuorumCertificate {
            group_id: "pool:forged".into(),
            epoch: 1,
            term: 0,
            slot: 7,
            proposal_hash: hash_lease_proposal("pool:forged", "lse_forged", "r1", "node-a", "w1", 1, t0, t0 + 30_000),
            mode: ConsensusMode::CftFastPath,
            votes: vec![], // Forged: zero signatures!
        },
    };
    forged_db
        .client
        .query("CREATE type::record('sys_mesh_decision_log', 'forged_7') CONTENT $l;")
        .bind(("l", serde_json::to_value(&forged_lease).unwrap()))
        .await
        .unwrap();
    assert!(
        forged_grp.recover_and_commit_slot(7, vec![]).await.is_err(),
        "Forged durable decision MUST fail closed on recover_and_commit_slot even with empty voter locks!"
    );
    assert!(
        CoordinationGroup::open_durable(
            forged_db.clone(),
            "pool:forged",
            ConsensusMode::CftFastPath,
            members.clone(),
        )
        .await
        .is_err(),
        "Forged durable decision MUST fail closed on open_durable boot!"
    );

    let malformed_db = Arc::new(Database::open_mem());
    let mut malformed_grp = CoordinationGroup::open_durable(
        malformed_db.clone(),
        "pool:malformed",
        ConsensusMode::CftFastPath,
        members.clone(),
    )
    .await
    .unwrap();
    malformed_db
        .client
        .query("CREATE type::record('sys_mesh_decision_log', 'bad_json') CONTENT $l;")
        .bind(("l", serde_json::json!({ "group_id": "pool:malformed", "corrupted": true })))
        .await
        .unwrap();
    assert!(
        malformed_grp.recover_and_commit_slot(1, vec![]).await.is_err(),
        "Malformed JSON record in sys_mesh_decision_log MUST fail closed on recovery!"
    );
    assert!(
        CoordinationGroup::open_durable(
            malformed_db.clone(),
            "pool:malformed",
            ConsensusMode::CftFastPath,
            members.clone(),
        )
        .await
        .is_err(),
        "Malformed JSON record in sys_mesh_decision_log MUST fail closed on open_durable!"
    );

    // 6. Commit-time expiration check: already-expired lease MUST NOT enter durable decision log!
    let exp_prop = LeaseProposal {
        group_id: "pool:us-east".into(),
        lease_id: "lse_expired_commit".into(),
        resource_key: "gpu:expired".into(),
        holder_node_id: "node-b".into(),
        workload_id: "wl-exp".into(),
        fencing_epoch: 1,
        issued_at_ms: t0 - 20_000,
        expires_at_ms: t0 - 1,
    };
    let exp_hash = exp_prop.canonical_digest();
    let exp_votes = vec![
        sign_vote_raw("pool:us-east", 1, group.next_slot, &exp_hash, "node-a", &sk_a).unwrap(),
        sign_vote_raw("pool:us-east", 1, group.next_slot, &exp_hash, "node-b", &sk_b).unwrap(),
        sign_vote_raw("pool:us-east", 1, group.next_slot, &exp_hash, "node-c", &sk_c).unwrap(),
    ];
    assert!(
        group
            .commit_exclusive_lease(
                "lse_expired_commit",
                "gpu:expired",
                "node-b",
                "wl-exp",
                t0 - 20_000,
                t0 - 1,
                t0,
                exp_votes,
            )
            .await
            .is_err(),
        "commit_exclusive_lease MUST reject already-expired leases!"
    );

    // 7. Milestone 1: Unified Durable Membership-Transition Consensus & All Acceptance Gates!
    // Existing slot 1 decision at epoch 1 MUST remain idempotently recoverable
    let idemp = group.recover_and_commit_slot(1, vec![]).await.unwrap();
    assert_eq!(idemp.unwrap().as_lease().unwrap().lease_id, dec1.lease.lease_id);

    // 7a. Lease proposal vs. Membership proposal at same slot -> EXACTLY ONE durable lock wins!
    let epoch2_members = vec![members[0].clone(), members[1].clone(), members[2].clone()];
    let race_slot = 77;
    let lease_race = LeaseProposal {
        group_id: "pool:us-east".into(),
        lease_id: "lse_race".into(),
        resource_key: "gpu:race".into(),
        holder_node_id: "node-a".into(),
        workload_id: "wl-race".into(),
        fencing_epoch: 1,
        issued_at_ms: t0,
        expires_at_ms: t0 + 30_000,
    };
    let mem_race = MembershipTransitionProposal::new(
        "pool:us-east",
        1,
        2,
        race_slot,
        ConsensusMode::CftFastPath,
        epoch2_members.clone(),
    )
    .unwrap();
    // Domain separation: lease and membership digests cannot be cross-interpreted
    assert_ne!(lease_race.canonical_digest(), mem_race.canonical_digest().unwrap());
    // Lock slot 77 with Lease -> Membership at slot 77 MUST be rejected!
    let _ = voter_a
        .cast_vote(&VoteRequest::for_lease(1, race_slot, lease_race.clone()))
        .await
        .unwrap();
    assert!(
        voter_a
            .cast_vote(&VoteRequest::for_membership(mem_race.clone()).unwrap())
            .await
            .is_err(),
        "Voter locked on Lease at slot 77 MUST reject Membership transition at same slot!"
    );
    // Lock slot 78 with Membership -> Lease at slot 78 MUST be rejected!
    let mem_race_78 = MembershipTransitionProposal::new(
        "pool:us-east",
        1,
        2,
        78,
        ConsensusMode::CftFastPath,
        epoch2_members.clone(),
    )
    .unwrap();
    let _ = voter_a
        .cast_vote(&VoteRequest::for_membership(mem_race_78).unwrap())
        .await
        .unwrap();
    assert!(
        voter_a
            .cast_vote(&VoteRequest::for_lease(1, 78, lease_race))
            .await
            .is_err(),
        "Voter locked on Membership at slot 78 MUST reject Lease at same slot!"
    );

    // 7b. On-disk voter restart: same membership proposal retried -> idempotent OK; different -> REJECTED!
    let voter_disk_dir = std::env::temp_dir().join(format!("nexus_m1_voter_{}", uuid::Uuid::new_v4().simple()));
    let reconf_slot = group.next_slot;
    let epoch2_prop = MembershipTransitionProposal::new(
        "pool:us-east",
        1,
        2,
        reconf_slot,
        ConsensusMode::CftFastPath,
        epoch2_members.clone(),
    )
    .unwrap();
    let epoch2_req = VoteRequest::for_membership(epoch2_prop.clone()).unwrap();
    let sig_before_restart = {
        let vdb = Arc::new(Database::init_in(&voter_disk_dir).await);
        let v_disk = VoterNode::new("node-a", sk_a.clone(), vdb).with_legacy_term_zero_compat();
        v_disk.cast_vote(&epoch2_req).await.unwrap()
    };
    {
        let vdb_reopened = Arc::new(Database::init_in(&voter_disk_dir).await);
        let v_disk_reopened = VoterNode::new("node-a", sk_a.clone(), vdb_reopened).with_legacy_term_zero_compat();
        let sig_after_restart = v_disk_reopened.cast_vote(&epoch2_req).await.unwrap();
        assert_eq!(sig_before_restart.signature, sig_after_restart.signature);

        // Different membership proposal at same (group, epoch, slot) after restart -> REJECTED!
        let alt_members = vec![members[0].clone(), members[1].clone(), members[3].clone()];
        let alt_prop = MembershipTransitionProposal::new(
            "pool:us-east",
            1,
            2,
            reconf_slot,
            ConsensusMode::CftFastPath,
            alt_members,
        )
        .unwrap();
        assert!(
            v_disk_reopened
                .cast_vote(&VoteRequest::for_membership(alt_prop).unwrap())
                .await
                .is_err(),
            "Different membership proposal after voter restart MUST be rejected!"
        );
    }
    let _ = std::fs::remove_dir_all(&voter_disk_dir);

    // 7c. Wrong predecessor epoch, wrong slot, and wrong mode -> ALL REJECTED!
    let bad_prev_prop = MembershipTransitionProposal::new(
        "pool:us-east",
        2,
        3,
        reconf_slot,
        ConsensusMode::CftFastPath,
        epoch2_members.clone(),
    )
    .unwrap();
    assert!(
        group
            .reconfigure_membership_with_quorum(&bad_prev_prop, vec![])
            .await
            .is_err(),
        "Wrong predecessor epoch MUST be rejected!"
    );
    let bad_slot_prop = MembershipTransitionProposal::new(
        "pool:us-east",
        1,
        2,
        reconf_slot + 5,
        ConsensusMode::CftFastPath,
        epoch2_members.clone(),
    )
    .unwrap();
    assert!(
        group
            .reconfigure_membership_with_quorum(&bad_slot_prop, vec![])
            .await
            .is_err(),
        "Wrong slot MUST be rejected!"
    );
    let bad_mode_prop = MembershipTransitionProposal::new(
        "pool:us-east",
        1,
        2,
        reconf_slot,
        ConsensusMode::BftSigned,
        epoch2_members.clone(),
    )
    .unwrap();
    assert!(
        group
            .reconfigure_membership_with_quorum(&bad_mode_prop, vec![])
            .await
            .is_err(),
        "Wrong consensus mode MUST be rejected!"
    );

    // 7d. Real durable voter locks -> quorum-certified membership transition to epoch 2!
    let mv_a = voter_a.cast_vote(&epoch2_req).await.unwrap();
    let mv_b = voter_b.cast_vote(&epoch2_req).await.unwrap();
    let mv_c = voter_c.cast_vote(&epoch2_req).await.unwrap();
    let mdec = group
        .reconfigure_membership_with_quorum(&epoch2_prop, vec![mv_a.clone(), mv_b.clone(), mv_c.clone()])
        .await
        .unwrap();
    assert_eq!(mdec.proposal.next_epoch, 2);
    assert_eq!(group.membership_epoch, 2);

    // 7e. Crash after commit before memory update / reboot: fresh open_durable reconstructs verified
    //     epoch chain 1 -> 2 AND still validates historical epoch-1 lease!
    let rebooted = CoordinationGroup::open_durable(
        db_coord.clone(),
        "pool:us-east",
        ConsensusMode::CftFastPath,
        epoch2_members.clone(),
    )
    .await
    .unwrap();
    assert_eq!(rebooted.membership_epoch, 2);
    assert!(rebooted.membership_history.contains_key(&1));
    assert!(rebooted.membership_history.contains_key(&2));
    assert_eq!(
        rebooted.active_leases.get("gpu:us-east:slot-0").unwrap().lease_id,
        dec1.lease.lease_id
    );

    // 7f. Old coordinator stuck at stale epoch 1 returns after transition -> CANNOT commit under stale epoch!
    let mut stale_coord = CoordinationGroup::new("pool:us-east", ConsensusMode::CftFastPath, members.clone());
    // Stale coordinator tries to commit another epoch 1 -> 2 transition on the shared DB -> rejected
    // because slot 2 is already committed (and any conflicting epoch-1 decision fails closed)
    let stale_alt_members = vec![members[0].clone(), members[1].clone(), members[3].clone()];
    let stale_alt_prop = MembershipTransitionProposal::new(
        "pool:us-east",
        1,
        2,
        reconf_slot,
        ConsensusMode::CftFastPath,
        stale_alt_members,
    )
    .unwrap();
    assert!(
        stale_coord
            .reconfigure_membership_with_quorum(&stale_alt_prop, vec![mv_a, mv_b, mv_c])
            .await
            .is_err(),
        "Stale coordinator MUST NOT commit conflicting transition!"
    );

    // 7g. Atomic 3-record transaction rollback test in real nexus-db!
    // Pre-insert ONLY `sys_mesh_membership_history` for epoch 2 so statement #1 (`CREATE sys_mesh_decision_log`)
    // executes inside BEGIN TRANSACTION, then statement #2 (`CREATE sys_mesh_membership_history`) fails with
    // `DbError::AlreadyExists` -> verify statement #1 was ROLLED BACK and active epoch remains 1!
    let rb_db = Arc::new(Database::open_mem());
    let mut rb_grp = CoordinationGroup::open_durable(
        rb_db.clone(),
        "pool:rollback",
        ConsensusMode::CftFastPath,
        members.clone(),
    )
    .await
    .unwrap();
    let rb_hkey = format!(
        "{}_e2",
        &blake3::hash(b"pool:rollback").to_hex().as_str()[..16]
    );
    rb_db
        .client
        .query("CREATE type::record('sys_mesh_membership_history', $hkey) CONTENT $h;")
        .bind(("hkey", rb_hkey))
        .bind((
            "h",
            serde_json::json!({
                "group_id": "pool:rollback",
                "membership_epoch": 2,
                "mode": "cft_fast_path",
                "members": epoch2_members,
                "transition": null,
            }),
        ))
        .await
        .unwrap();
    let rb_prop = MembershipTransitionProposal::new(
        "pool:rollback",
        1,
        2,
        1,
        ConsensusMode::CftFastPath,
        epoch2_members.clone(),
    )
    .unwrap();
    let rb_req = VoteRequest::for_membership(rb_prop.clone()).unwrap();
    let rb_votes = vec![
        voter_a.cast_vote(&rb_req).await.unwrap(),
        voter_b.cast_vote(&rb_req).await.unwrap(),
        voter_c.cast_vote(&rb_req).await.unwrap(),
    ];
    assert!(
        rb_grp
            .reconfigure_membership_with_quorum(&rb_prop, rb_votes)
            .await
            .is_err(),
        "Transaction MUST fail when history record already exists!"
    );
    // Verify statement #1 (`sys_mesh_decision_log`) was ROLLED BACK (zero rows) and in-memory epoch stayed 1!
    let mut rb_check = rb_db
        .client
        .query("SELECT * FROM sys_mesh_decision_log")
        .await
        .unwrap();
    let rb_rows: Vec<serde_json::Value> = rb_check.take(0).unwrap_or_default();
    assert!(
        rb_rows.is_empty(),
        "Atomic transaction rollback FAILED: orphaned decision log row remained after history conflict!"
    );
    assert_eq!(rb_grp.membership_epoch, 1);

    // 7h. Unproven epoch (transition: null), skipped epoch (1 -> 3), tampered tip, and same-hash forged QC
    //     MUST ALL fail closed on open_durable!
    assert!(
        CoordinationGroup::open_durable(
            rb_db.clone(),
            "pool:rollback",
            ConsensusMode::CftFastPath,
            members.clone(),
        )
        .await
        .is_err(),
        "Unproven epoch 2 (transition: null) MUST fail closed on open_durable!"
    );

    let skip_db = Arc::new(Database::open_mem());
    let _ = CoordinationGroup::open_durable(
        skip_db.clone(),
        "pool:skip",
        ConsensusMode::CftFastPath,
        members.clone(),
    )
    .await
    .unwrap();
    let skip_hkey = format!("{}_e3", &blake3::hash(b"pool:skip").to_hex().as_str()[..16]);
    skip_db
        .client
        .query("CREATE type::record('sys_mesh_membership_history', $hkey) CONTENT $h;")
        .bind(("hkey", skip_hkey))
        .bind((
            "h",
            serde_json::json!({
                "group_id": "pool:skip",
                "membership_epoch": 3,
                "mode": "cft_fast_path",
                "members": epoch2_members,
                "transition": null,
            }),
        ))
        .await
        .unwrap();
    assert!(
        CoordinationGroup::open_durable(
            skip_db.clone(),
            "pool:skip",
            ConsensusMode::CftFastPath,
            members.clone(),
        )
        .await
        .is_err(),
        "Skipped epoch (1 -> 3) MUST fail closed on open_durable!"
    );

    // Same-hash forged QC already present in `sys_mesh_decision_log` MUST fail closed!
    let forged_m_db = Arc::new(Database::open_mem());
    let mut forged_m_grp = CoordinationGroup::open_durable(
        forged_m_db.clone(),
        "pool:forged-mem",
        ConsensusMode::CftFastPath,
        members.clone(),
    )
    .await
    .unwrap();
    let fm_prop = MembershipTransitionProposal::new(
        "pool:forged-mem",
        1,
        2,
        1,
        ConsensusMode::CftFastPath,
        epoch2_members.clone(),
    )
    .unwrap();
    let fm_hash = fm_prop.canonical_digest().unwrap();
    let fm_skey = format!(
        "{}_e1_s1",
        &blake3::hash(b"pool:forged-mem").to_hex().as_str()[..16]
    );
    forged_m_db
        .client
        .query("CREATE type::record('sys_mesh_decision_log', $skey) CONTENT $d;")
        .bind(("skey", fm_skey))
        .bind((
            "d",
            serde_json::json!({
                "decision_kind": "membership",
                "proposal": fm_prop,
                "qc": {
                    "group_id": "pool:forged-mem",
                    "epoch": 1,
                    "slot": 1,
                    "proposal_hash": fm_hash,
                    "mode": "cft_fast_path",
                    "votes": []
                }
            }),
        ))
        .await
        .unwrap();
    let fm_req = VoteRequest::for_membership(fm_prop.clone()).unwrap();
    let fm_votes = vec![
        voter_a.cast_vote(&fm_req).await.unwrap(),
        voter_b.cast_vote(&fm_req).await.unwrap(),
        voter_c.cast_vote(&fm_req).await.unwrap(),
    ];
    assert!(
        forged_m_grp
            .reconfigure_membership_with_quorum(&fm_prop, fm_votes)
            .await
            .is_err(),
        "Existing decision record with matching hash but forged QC MUST fail closed!"
    );

    // 7i. Milestone 1.1: Strict recovery rejects mixed proposal-bound + payload-less locks,
    //     and corrupt lock record returns Err from query_slot_lock() (not Ok(None))!
    let mix_prop = LeaseProposal {
        group_id: "pool:us-east".into(),
        lease_id: "lse_mix".into(),
        resource_key: "gpu:mix".into(),
        holder_node_id: "node-b".into(),
        workload_id: "wl-mix".into(),
        fencing_epoch: 1,
        issued_at_ms: t0,
        expires_at_ms: t0 + 30_000,
    };
    let mix_hash = mix_prop.canonical_digest();
    let mv1 = sign_vote_raw("pool:us-east", 1, 61, &mix_hash, "node-a", &sk_a).unwrap();
    let mv2 = sign_vote_raw("pool:us-east", 1, 61, &mix_hash, "node-b", &sk_b).unwrap();
    let mv3 = sign_vote_raw("pool:us-east", 1, 61, &mix_hash, "node-c", &sk_c).unwrap();
    assert!(
        rec_group
            .recover_and_commit_slot(
                61,
                vec![
                    (mv1, Some(SlotProposal::Lease(mix_prop))),
                    (mv2, None),
                    (mv3, None),
                ],
            )
            .await
            .is_err(),
        "Recovery MUST fail closed on mixed proposal-bound + payload-less voter locks!"
    );
    let corrupt_lock_key = legacy_voter.slot_lock_key("pool:us-east", 1, 99);
    legacy_db
        .client
        .query("CREATE type::record('sys_mesh_voter_lock', $id) CONTENT { corrupted: true };")
        .bind(("id", corrupt_lock_key))
        .await
        .unwrap();
    assert!(
        legacy_voter.query_slot_lock("pool:us-east", 1, 99).await.is_err(),
        "Corrupt durable voter lock MUST return Err from query_slot_lock (not Ok(None))!"
    );
    assert!(
        legacy_voter.query_slot_lock("pool:us-east", 1, 98).await.unwrap().is_none(),
        "Absent durable voter lock must still return Ok(None)!"
    );

    // 7i-2. Milestone 1.2: Misbound lock_key, group_id, epoch, slot, or voter_node_id MUST fail closed
    //       in query_slot_lock(), AND unexpected lock identity MUST fail closed in recover_and_commit_slot()!
    let misbound_cases = [
        ("wrong_lock_key", 101u64, "WRONG_KEY", "pool:us-east", 1u64, 101u64, "node-a"),
        ("wrong_group", 102, "", "pool:other", 1, 102, "node-a"),
        ("wrong_epoch", 103, "", "pool:us-east", 9, 103, "node-a"),
        ("wrong_slot", 104, "", "pool:us-east", 1, 999, "node-a"),
        ("wrong_voter", 105, "", "pool:us-east", 1, 105, "node-b"),
    ];
    for (label, lookup_slot, override_key, stored_gid, stored_ep, stored_slot, stored_voter) in misbound_cases {
        let lk = legacy_voter.slot_lock_key("pool:us-east", 1, lookup_slot);
        let stored_lk = if override_key.is_empty() { lk.clone() } else { override_key.to_string() };
        legacy_db
            .client
            .query("CREATE type::record('sys_mesh_voter_lock', $id) CONTENT $l;")
            .bind(("id", lk))
            .bind((
                "l",
                serde_json::json!({
                    "lock_key": stored_lk,
                    "group_id": stored_gid,
                    "epoch": stored_ep,
                    "slot": stored_slot,
                    "proposal_hash": mix_hash,
                    "voter_node_id": stored_voter,
                    "signature": "sig",
                    "locked_at_ms": t0,
                }),
            ))
            .await
            .unwrap();
        assert!(
            legacy_voter.query_slot_lock("pool:us-east", 1, lookup_slot).await.is_err(),
            "query_slot_lock MUST fail closed on misbound case '{}'!",
            label
        );
    }
    let wrong_slot_vote = sign_vote_raw("pool:us-east", 1, 999, &mix_hash, "node-a", &sk_a).unwrap();
    assert!(
        rec_group
            .recover_and_commit_slot(62, vec![(wrong_slot_vote, None)])
            .await
            .is_err(),
        "recover_and_commit_slot MUST fail closed on unexpected (group/epoch/slot) entry!"
    );

    // 7j. Milestone 1.1: Genesis guard rejects pre-existing same-group OR ambiguous decision-log rows,
    //     while allowing positively foreign-group decision-log rows!
    let orphan_db = Arc::new(Database::open_mem());
    orphan_db
        .client
        .query("DEFINE TABLE IF NOT EXISTS sys_mesh_decision_log SCHEMALESS; CREATE type::record('sys_mesh_decision_log', 'orphan1') CONTENT { group_id: 'pool:orphan', lease_id: 'x' };")
        .await
        .unwrap();
    assert!(
        CoordinationGroup::open_durable(
            orphan_db.clone(),
            "pool:orphan",
            ConsensusMode::CftFastPath,
            members.clone(),
        )
        .await
        .is_err(),
        "Genesis MUST fail closed when a decision-log record already exists for the same group!"
    );
    // Positively foreign group initializes cleanly on the same DB
    let _ = CoordinationGroup::open_durable(
        orphan_db.clone(),
        "pool:other-clean",
        ConsensusMode::CftFastPath,
        members.clone(),
    )
    .await
    .unwrap();
    // Ambiguous/malformed row without `group_id` blocks genesis!
    let ambig_db = Arc::new(Database::open_mem());
    ambig_db
        .client
        .query("DEFINE TABLE IF NOT EXISTS sys_mesh_decision_log SCHEMALESS; CREATE type::record('sys_mesh_decision_log', 'ambig1') CONTENT { broken: true };")
        .await
        .unwrap();
    assert!(
        CoordinationGroup::open_durable(
            ambig_db,
            "pool:ambig",
            ConsensusMode::CftFastPath,
            members.clone(),
        )
        .await
        .is_err(),
        "Genesis MUST fail closed when an ambiguous/malformed decision-log row exists!"
    );

    // 7k. Milestone 1.1: Regressed `sys_mesh_membership.next_slot` fails closed on boot (no silent repair!),
    //     and inconsistent 3-record active tip rejects idempotent membership retry!
    let tamper_ns_db = Arc::new(Database::open_mem());
    let mut tamper_ns_grp = CoordinationGroup::open_durable(
        tamper_ns_db.clone(),
        "pool:next-slot-check",
        ConsensusMode::CftFastPath,
        members.clone(),
    )
    .await
    .unwrap();
    let tn_prop = MembershipTransitionProposal::new(
        "pool:next-slot-check",
        1,
        2,
        1,
        ConsensusMode::CftFastPath,
        epoch2_members.clone(),
    )
    .unwrap();
    let tn_req = VoteRequest::for_membership(tn_prop.clone()).unwrap();
    let tn_votes = vec![
        voter_a.cast_vote(&tn_req).await.unwrap(),
        voter_b.cast_vote(&tn_req).await.unwrap(),
        voter_c.cast_vote(&tn_req).await.unwrap(),
    ];
    let mut pre_commit_retry_grp = tamper_ns_grp.clone();
    let _ = tamper_ns_grp
        .reconfigure_membership_with_quorum(&tn_prop, tn_votes.clone())
        .await
        .unwrap();
    // Exact idempotent retry while all 3 records are consistent -> SUCCEEDS!
    let mut clean_retry_grp = pre_commit_retry_grp.clone();
    let _ = clean_retry_grp
        .reconfigure_membership_with_quorum(&tn_prop, tn_votes.clone())
        .await
        .unwrap();
    // Tamper ONLY `next_slot` back to 1 (regressed behind committed slot 1 -> requires >= 2)
    let tn_gkey = blake3::hash(b"pool:next-slot-check").to_hex().to_string();
    tamper_ns_db
        .client
        .query("UPSERT type::record('sys_mesh_membership', $gkey) CONTENT $m;")
        .bind(("gkey", tn_gkey.clone()))
        .bind((
            "m",
            serde_json::json!({
                "group_id": "pool:next-slot-check",
                "mode": "cft_fast_path",
                "membership_epoch": 2,
                "next_slot": 1,
                "members": epoch2_members,
            }),
        ))
        .await
        .unwrap();
    assert!(
        CoordinationGroup::open_durable(
            tamper_ns_db.clone(),
            "pool:next-slot-check",
            ConsensusMode::CftFastPath,
            epoch2_members.clone(),
        )
        .await
        .is_err(),
        "open_durable MUST fail closed when sys_mesh_membership.next_slot is regressed!"
    );
    // Also verify idempotent retry directly rejects regressed next_slot AND unproven epoch 3!
    assert!(
        pre_commit_retry_grp
            .reconfigure_membership_with_quorum(&tn_prop, tn_votes.clone())
            .await
            .is_err(),
        "Idempotent membership retry MUST reject regressed sys_mesh_membership.next_slot!"
    );
    tamper_ns_db
        .client
        .query("UPSERT type::record('sys_mesh_membership', $gkey) CONTENT $m;")
        .bind(("gkey", tn_gkey))
        .bind((
            "m",
            serde_json::json!({
                "group_id": "pool:next-slot-check",
                "mode": "cft_fast_path",
                "membership_epoch": 3,
                "next_slot": 5,
                "members": epoch2_members,
            }),
        ))
        .await
        .unwrap();
    assert!(
        pre_commit_retry_grp
            .reconfigure_membership_with_quorum(&tn_prop, tn_votes)
            .await
            .is_err(),
        "Idempotent membership retry MUST reject unproven successor epoch 3 in sys_mesh_membership!"
    );
    assert!(
        CoordinationGroup::open_durable(
            tamper_ns_db,
            "pool:next-slot-check",
            ConsensusMode::CftFastPath,
            epoch2_members.clone(),
        )
        .await
        .is_err(),
        "Unproven epoch 3 tip MUST fail closed on open_durable!"
    );

    // 8. Typed `nexus_db::DbError::AlreadyExists` survives full query & transaction pipeline!
    let dup_db = Database::open_mem();
    dup_db
        .client
        .query("DEFINE TABLE IF NOT EXISTS sys_typed_dup SCHEMALESS; CREATE type::record('sys_typed_dup', 'k1') CONTENT { v: 1 };")
        .await
        .unwrap();
    let standalone_err = dup_db
        .client
        .query("CREATE type::record('sys_typed_dup', 'k1') CONTENT { v: 2 };")
        .await
        .err()
        .expect("Duplicate standalone CREATE must fail");
    assert!(
        is_already_exists_error(&standalone_err),
        "Typed DbError::AlreadyExists must survive standalone query_scoped!"
    );
    let tx_err = dup_db
        .client
        .query("BEGIN TRANSACTION; CREATE type::record('sys_typed_dup', 'k1') CONTENT { v: 3 }; COMMIT TRANSACTION;")
        .await
        .err()
        .expect("Duplicate transactional CREATE must fail");
    assert!(
        is_already_exists_error(&tx_err),
        "Typed DbError::AlreadyExists must survive BEGIN/COMMIT transaction!"
    );
    let fake_string_err = anyhow::anyhow!("Record sys_typed_dup:k1 already exists");
    assert!(
        !is_already_exists_error(&fake_string_err),
        "is_already_exists_error MUST NOT match untyped string errors!"
    );

    // 9. Membership-transition digest & BFT equivocation
    let mut swapped_members = members.clone();
    swapped_members[0].ed25519_pubkey = "FAKE_SUBSTITUTED_PUBKEY".into();
    assert_ne!(
        hash_membership_change("pool:us-east", 2, ConsensusMode::CftFastPath, &members).unwrap(),
        hash_membership_change("pool:us-east", 2, ConsensusMode::CftFastPath, &swapped_members).unwrap()
    );
    let mut bft_group = CoordinationGroup::new("open:global", ConsensusMode::BftSigned, members);
    let h1 = hash_lease_proposal("open:global", "l1", "open:gpu:1", "node-c", "wl-1", 1, t0, t0 + 10_000);
    let h2 = hash_lease_proposal("open:global", "l2", "open:gpu:1", "node-b", "wl-evil", 1, t0, t0 + 10_000);
    let v1 = sign_vote_raw("open:global", 1, 1, &h1, "node-b", &sk_b).unwrap();
    let v2 = sign_vote_raw("open:global", 1, 1, &h2, "node-b", &sk_b).unwrap();
    assert!(bft_group.record_and_verify_vote(&v1).unwrap().is_none());
    assert!(bft_group.record_and_verify_vote(&v2).unwrap().is_some());

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[tokio::test]
async fn milestone2_durable_terms_adoption_epoch_install_and_contiguous_takeover() {
    let db_idp = Arc::new(Database::open_mem());
    let idp = NexusIdp::new(db_idp.clone());
    let org = idp
        .create_org("root", "m2-org", "Milestone 2 Org", None, None, OrgPolicyPatch::default())
        .await
        .unwrap();
    let (id_a, sk_a) = idp.create_identity("m2-a", None).await.unwrap();
    let (id_b, sk_b) = idp.create_identity("m2-b", None).await.unwrap();
    let (id_c, sk_c) = idp.create_identity("m2-c", None).await.unwrap();
    let (id_d, sk_d) = idp.create_identity("m2-d", None).await.unwrap();

    let m_a = GroupMember { node_id: "node-a".into(), identity_id: id_a.identity_id, org_id: org.org_id.clone(), ed25519_pubkey: id_a.active_pubkey };
    let m_b = GroupMember { node_id: "node-b".into(), identity_id: id_b.identity_id, org_id: org.org_id.clone(), ed25519_pubkey: id_b.active_pubkey };
    let m_c = GroupMember { node_id: "node-c".into(), identity_id: id_c.identity_id, org_id: org.org_id.clone(), ed25519_pubkey: id_c.active_pubkey };
    let m_d = GroupMember { node_id: "node-d".into(), identity_id: id_d.identity_id, org_id: org.org_id.clone(), ed25519_pubkey: id_d.active_pubkey };

    let epoch1_members = vec![m_a.clone(), m_b.clone(), m_c.clone()];
    let voter_a = VoterNode::new("node-a", sk_a.clone(), Arc::new(Database::open_mem())).with_legacy_term_zero_compat();
    let voter_b = VoterNode::new("node-b", sk_b.clone(), Arc::new(Database::open_mem())).with_legacy_term_zero_compat();
    let voter_c = VoterNode::new("node-c", sk_c.clone(), Arc::new(Database::open_mem())).with_legacy_term_zero_compat();
    let voter_d = VoterNode::new("node-d", sk_d.clone(), Arc::new(Database::open_mem())).with_legacy_term_zero_compat();
    for v in [&voter_a, &voter_b, &voter_c] {
        v.install_genesis_epoch("pool:m2", ConsensusMode::CftFastPath, epoch1_members.clone())
            .await
            .unwrap();
    }

    let t0 = CoordinationGroup::now_ms();

    // 1 & 2. Same-term prepare retry (same leader -> idempotent OK; different leader -> REJECTED!)
    let prep1 = PrepareTermRequest {
        group_id: "pool:m2".into(),
        epoch: 1,
        term: 1,
        leader_id: "coord-1".into(),
        from_slot: 1,
    };
    let p1_a = voter_a.prepare_term(&prep1).await.unwrap();
    let p1_a_retry = voter_a.prepare_term(&prep1).await.unwrap();
    assert_eq!(p1_a.signature, p1_a_retry.signature, "Same-leader prepare retry must be idempotent!");

    let prep1_rival = PrepareTermRequest {
        leader_id: "coord-rival".into(),
        ..prep1.clone()
    };
    assert!(
        voter_a.prepare_term(&prep1_rival).await.is_err(),
        "Same-term prepare from different leader MUST be rejected!"
    );

    // 9. Competing standbys in same term: at most ONE can obtain a valid quorum!
    // voter_a already promised coord-1; voter_b promises coord-rival; voter_c promises coord-1 -> coord-1 gets 2/3, rival gets 1/3!
    let _p1_b_rival = voter_b.prepare_term(&prep1_rival).await.unwrap();
    let p1_c = voter_c.prepare_term(&prep1).await.unwrap();
    let coord1_db = Arc::new(Database::open_mem());
    let coord1 = CoordinationGroup::open_durable(
        coord1_db.clone(),
        "pool:m2",
        ConsensusMode::CftFastPath,
        epoch1_members.clone(),
    )
    .await
    .unwrap();
    let (cert_t1, _) = coord1
        .plan_takeover_from_promises("coord-1", 1, 1, vec![p1_a, p1_c])
        .unwrap();
    assert!(
        coord1
            .plan_takeover_from_promises("coord-rival", 1, 1, vec![_p1_b_rival])
            .is_err(),
        "Competing standby with only 1/3 promises MUST fail quorum!"
    );

    // 3. Higher-term vote WITHOUT Phase-1 TermCertificate -> REJECTED!
    let lp_s1 = LeaseProposal {
        group_id: "pool:m2".into(),
        lease_id: "lse_s1".into(),
        resource_key: "gpu:m2:0".into(),
        holder_node_id: "node-a".into(),
        workload_id: "wl-1".into(),
        fencing_epoch: 1,
        issued_at_ms: t0,
        expires_at_ms: t0 + 120_000,
    };
    let no_cert_req = VoteRequest {
        group_id: "pool:m2".into(),
        epoch: 1,
        slot: 1,
        proposal_hash: lp_s1.canonical_digest(),
        proposal: Some(SlotProposal::Lease(lp_s1.clone())),
        term: 1,
        leader_id: Some("coord-1".into()),
        term_cert: None,
    };
    assert!(
        voter_a.cast_vote(&no_cert_req).await.is_err(),
        "Higher-term vote WITHOUT Phase-1 TermCertificate MUST be rejected!"
    );

    // Accept slot 1 AND slot 3 (leaving slot 2 as an unaccepted GAP!) in term 1 on voter_a & voter_c
    let s1_req = VoteRequest::for_lease(1, 1, lp_s1.clone()).with_term(1, "coord-1", cert_t1.clone());
    let _ = voter_a.cast_vote(&s1_req).await.unwrap();
    let _ = voter_c.cast_vote(&s1_req).await.unwrap();

    let lp_s3 = LeaseProposal {
        group_id: "pool:m2".into(),
        lease_id: "lse_s3".into(),
        resource_key: "gpu:m2:1".into(),
        holder_node_id: "node-b".into(),
        workload_id: "wl-3".into(),
        fencing_epoch: 1,
        issued_at_ms: t0,
        expires_at_ms: t0 + 120_000,
    };
    let s3_req = VoteRequest::for_lease(1, 3, lp_s3.clone()).with_term(1, "coord-1", cert_t1.clone());
    let _ = voter_a.cast_vote(&s3_req).await.unwrap();
    let _ = voter_c.cast_vote(&s3_req).await.unwrap();

    // 4. Higher-term vote with CONFLICTING adopted value -> REJECTED by voter!
    let prep2 = PrepareTermRequest {
        group_id: "pool:m2".into(),
        epoch: 1,
        term: 2,
        leader_id: "coord-2".into(),
        from_slot: 1,
    };
    let p2_a = voter_a.prepare_term(&prep2).await.unwrap();
    let p2_b = voter_b.prepare_term(&prep2).await.unwrap();
    let p2_c = voter_c.prepare_term(&prep2).await.unwrap();
    let (cert_t2, _) = coord1
        .plan_takeover_from_promises("coord-2", 2, 1, vec![p2_a.clone(), p2_b.clone(), p2_c.clone()])
        .unwrap();
    let conflicting_s1 = LeaseProposal {
        lease_id: "lse_s1_evil".into(),
        holder_node_id: "node-c".into(),
        ..lp_s1.clone()
    };
    let bad_adopt_req = VoteRequest::for_lease(1, 1, conflicting_s1)
        .with_term(2, "coord-2", cert_t2.clone());
    assert!(
        voter_a.cast_vote(&bad_adopt_req).await.is_err(),
        "Voter MUST reject higher-term vote that conflicts with adopted value from TermCertificate!"
    );

    // 10. Old coordinator (term 1) reconnects after term 2 takeover -> CANNOT obtain votes!
    assert!(
        voter_a.cast_vote(&s1_req).await.is_err(),
        "Old term-1 coordinator MUST be fenced at voter after term-2 promise!"
    );

    // 5. Two conflicting values with equal highest accepted_term -> takeover FAILS CLOSED!
    let mut conflict_p_a = p2_a.clone();
    let mut conflict_p_b = p2_b.clone();
    let alt_lp = LeaseProposal { lease_id: "lse_alt_conflict".into(), ..lp_s1.clone() };
    let alt_vote = sign_vote_raw_in_term("pool:m2", 1, 1, 1, &alt_lp.canonical_digest(), "node-b", &sk_b).unwrap();
    conflict_p_b.accepted_locks = vec![AcceptedSlotLock {
        epoch: 1,
        slot: 1,
        accepted_term: 1, // Equal highest accepted_term=1, conflicting proposal!
        proposal_hash: alt_lp.canonical_digest(),
        proposal: SlotProposal::Lease(alt_lp),
        vote: alt_vote,
    }];
    // Re-sign conflict_p_b legitimately as node-b to prove the adoption verifier catches equal-term conflicts!
    let conflict_payload = nexus_io::mesh::consensus::canonical_promise_payload(
        &conflict_p_b.group_id,
        conflict_p_b.epoch,
        conflict_p_b.term,
        &conflict_p_b.leader_id,
        conflict_p_b.from_slot,
        &conflict_p_b.voter_node_id,
        conflict_p_b.min_active_epoch,
        &conflict_p_b.accepted_locks,
    );
    conflict_p_b.signature = nexus_db::auth::ed25519_sign(&sk_b, &conflict_payload).unwrap();
    let conflict_cert = TermCertificate {
        group_id: "pool:m2".into(),
        epoch: 1,
        term: 2,
        leader_id: "coord-2".into(),
        from_slot: 1,
        mode: ConsensusMode::CftFastPath,
        promises: vec![conflict_p_a.clone(), conflict_p_b],
    };
    let ep1_cfg = MembershipEpochConfig {
        mode: ConsensusMode::CftFastPath,
        members: epoch1_members.iter().cloned().map(|m| (m.node_id.clone(), m)).collect(),
    };
    assert!(
        verify_term_certificate_and_adoption(&conflict_cert, &ep1_cfg, 1).is_err(),
        "Two conflicting proposals with equal highest accepted_term MUST fail closed!"
    );
    let _ = &mut conflict_p_a;

    // 6 & 11. Contiguous multi-slot takeover with GAP at slot 2 + crash/restart resume!
    let standby_db_dir = std::env::temp_dir().join(format!("nexus_m2_standby_{}", uuid::Uuid::new_v4().simple()));
    let standby_db = Arc::new(Database::init_in(&standby_db_dir).await);
    let mut coord2 = CoordinationGroup::open_durable(
        standby_db.clone(),
        "pool:m2",
        ConsensusMode::CftFastPath,
        epoch1_members.clone(),
    )
    .await
    .unwrap();
    let report = coord2
        .execute_takeover_catch_up("coord-2", 3, &[voter_a.clone(), voter_b.clone(), voter_c.clone()])
        .await
        .unwrap();
    assert_eq!(report.term, 3);
    assert_eq!(report.next_slot, 4);
    assert_eq!(report.recovered_slots, vec![1, 3]);
    assert_eq!(report.filled_gaps, vec![2], "Gap slot 2 MUST be filled with durable NoOp!");

    // Crash/restart coord-2 from disk -> contiguous verified prefix (slots 1, 2=NoOp, 3) survives!
    drop(coord2);
    drop(standby_db);
    let standby_db_reopened = Arc::new(Database::init_in(&standby_db_dir).await);
    let mut coord2_restarted = CoordinationGroup::open_durable(
        standby_db_reopened,
        "pool:m2",
        ConsensusMode::CftFastPath,
        epoch1_members.clone(),
    )
    .await
    .unwrap();
    assert_eq!(coord2_restarted.next_slot, 4);
    assert_eq!(coord2_restarted.current_term, 3);
    assert_eq!(coord2_restarted.active_leases.get("gpu:m2:0").unwrap().lease_id, "lse_s1");
    assert_eq!(coord2_restarted.active_leases.get("gpu:m2:1").unwrap().lease_id, "lse_s3");

    // 7 & 8. Membership transition (drop node-c, admit node-d) ->
    //        New member D CANNOT vote in epoch 2 until installing transition certificate;
    //        Removed member C rejects BOTH old epoch 1 AND new epoch 2 after installation!
    let epoch2_members = vec![m_a.clone(), m_b.clone(), m_d.clone()];
    let m_prop = MembershipTransitionProposal::new(
        "pool:m2",
        1,
        2,
        4,
        ConsensusMode::CftFastPath,
        epoch2_members.clone(),
    )
    .unwrap();
    let report_t4 = coord2_restarted
        .execute_takeover_catch_up("coord-2", 4, &[voter_a.clone(), voter_b.clone(), voter_c.clone()])
        .await
        .unwrap();
    let cert_t4 = coord2_restarted.active_term_cert.clone().unwrap();
    assert_eq!(report_t4.term, 4);

    let m_req = VoteRequest::for_membership(m_prop.clone())
        .unwrap()
        .with_term(4, "coord-2", cert_t4);
    let mv_a = voter_a.cast_vote(&m_req).await.unwrap();
    let mv_b = voter_b.cast_vote(&m_req).await.unwrap();
    let mdec = coord2_restarted
        .reconfigure_membership_with_quorum(&m_prop, vec![mv_a, mv_b])
        .await
        .unwrap();

    // New member D has NOT installed epoch 2 yet -> prepare_term in epoch 2 MUST fail!
    let prep_e2_t5 = PrepareTermRequest {
        group_id: "pool:m2".into(),
        epoch: 2,
        term: 5,
        leader_id: "coord-2".into(),
        from_slot: 5,
    };
    assert!(
        voter_d.prepare_term(&prep_e2_t5).await.is_err(),
        "New member D MUST NOT participate in epoch 2 before installing transition certificate!"
    );

    // Install verified transition certificate on A, B, C (anchored to epoch 1), and bootstrap
    // newly admitted D exclusively via trusted genesis chain!
    let m2_genesis_digest = hash_genesis_config("pool:m2", ConsensusMode::CftFastPath, &epoch1_members).unwrap();
    for v in [&voter_a, &voter_b, &voter_c] {
        v.install_membership_epoch(&mdec, &ep1_cfg).await.unwrap();
    }
    // Unanchored direct `install_membership_epoch` AND uninitialized `install_membership_chain_from_genesis` MUST fail!
    assert!(
        voter_d.install_membership_epoch(&mdec, &ep1_cfg).await.is_err(),
        "New voter D MUST reject unanchored install_membership_epoch!"
    );
    let missing_anchor_err = voter_d
        .install_membership_chain_from_genesis(
            "pool:m2",
            ConsensusMode::CftFastPath,
            epoch1_members.clone(),
            &[mdec.clone()],
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            missing_anchor_err.downcast_ref::<GenesisAnchorError>(),
            Some(GenesisAnchorError::MissingTrustedGenesisAnchor { .. })
        ),
        "Uninitialized voter MUST fail with typed MissingTrustedGenesisAnchor!"
    );
    // Independently provision trusted genesis anchor on D, then verify & install chain!
    voter_d
        .set_trusted_genesis_anchor("pool:m2", m2_genesis_digest)
        .await
        .unwrap();
    voter_d
        .install_membership_chain_from_genesis(
            "pool:m2",
            ConsensusMode::CftFastPath,
            epoch1_members.clone(),
            &[mdec],
        )
        .await
        .unwrap();

    // Now D CAN participate in epoch 2!
    let p5_d = voter_d.prepare_term(&prep_e2_t5).await.unwrap();
    assert_eq!(p5_d.min_active_epoch, 2);

    // Removed member C MUST reject BOTH old epoch 1 AND new epoch 2!
    let stale_e1_prep = PrepareTermRequest {
        group_id: "pool:m2".into(),
        epoch: 1,
        term: 6,
        leader_id: "old-coord".into(),
        from_slot: 1,
    };
    assert!(
        voter_c.prepare_term(&stale_e1_prep).await.is_err(),
        "Removed member C MUST reject old epoch 1!"
    );
    assert!(
        voter_c.prepare_term(&prep_e2_t5).await.is_err(),
        "Removed member C MUST reject new epoch 2!"
    );

    let _ = std::fs::remove_dir_all(&standby_db_dir);
}

#[tokio::test]
async fn milestone2_1_atomic_cas_dual_quorum_trusted_genesis_and_strict_promises() {
    use tokio::sync::Barrier;

    let db_idp = Arc::new(Database::open_mem());
    let idp = NexusIdp::new(db_idp.clone());
    let org = idp
        .create_org("root", "m21-org", "Milestone 2.1 Org", None, None, OrgPolicyPatch::default())
        .await
        .unwrap();
    let mut keys = Vec::new();
    let mut gm = Vec::new();
    for name in ["a", "b", "c", "d", "e", "f", "g", "h"] {
        let (id, sk) = idp.create_identity(&format!("m21-{}", name), None).await.unwrap();
        gm.push(GroupMember {
            node_id: format!("node-{}", name),
            identity_id: id.identity_id,
            org_id: org.org_id.clone(),
            ed25519_pubkey: id.active_pubkey,
        });
        keys.push(sk);
    }

    let t0 = CoordinationGroup::now_ms();
    let old_members = gm[0..5].to_vec(); // a, b, c, d, e (quorum = 3)
    let new_members = vec![gm[0].clone(), gm[1].clone(), gm[5].clone(), gm[6].clone(), gm[7].clone()]; // a, b, f, g, h (quorum = 3)
    let genesis_digest = hash_genesis_config("pool:m21", ConsensusMode::CftFastPath, &old_members).unwrap();

    // 1. P1 Explicit production term-zero policy: default VoterNode::new() MUST reject term == 0!
    let prod_voter = VoterNode::new("node-a", keys[0].clone(), Arc::new(Database::open_mem()));
    let lp0 = LeaseProposal {
        group_id: "pool:m21".into(),
        lease_id: "lse_term0".into(),
        resource_key: "gpu:0".into(),
        holder_node_id: "node-a".into(),
        workload_id: "wl-0".into(),
        fencing_epoch: 1,
        issued_at_ms: t0,
        expires_at_ms: t0 + 60_000,
    };
    assert!(
        prod_voter.cast_vote(&VoteRequest::for_lease(1, 1, lp0.clone())).await.is_err(),
        "Default production VoterNode MUST reject term-0 VoteRequest!"
    );

    // 2. P0 Concurrent competing prepare_term race across SEPARATE VoterNode instances sharing ONE durable DB!
    let shared_voter_db = Arc::new(Database::open_mem());
    let va_1 = VoterNode::new("node-a", keys[0].clone(), shared_voter_db.clone());
    let va_2 = VoterNode::new("node-a", keys[0].clone(), shared_voter_db.clone());
    va_1.install_genesis_epoch("pool:m21", ConsensusMode::CftFastPath, old_members.clone())
        .await
        .unwrap();

    // 2a. Competing terms 5 vs 6 -> durable promised_term MUST end at 6 (never regress to 5!)
    let b1 = Arc::new(Barrier::new(2));
    let (r5, r6) = tokio::join!(
        {
            let b = b1.clone();
            let v = va_1.clone();
            async move {
                b.wait().await;
                v.prepare_term(&PrepareTermRequest {
                    group_id: "pool:m21".into(),
                    epoch: 1,
                    term: 5,
                    leader_id: "leader-5".into(),
                    from_slot: 1,
                })
                .await
            }
        },
        {
            let b = b1.clone();
            let v = va_2.clone();
            async move {
                b.wait().await;
                v.prepare_term(&PrepareTermRequest {
                    group_id: "pool:m21".into(),
                    epoch: 1,
                    term: 6,
                    leader_id: "leader-6".into(),
                    from_slot: 1,
                })
                .await
            }
        }
    );
    assert!(r6.is_ok(), "Higher term 6 must succeed");
    let _ = r5;
    // Verify durable promised_term is 6 by rejecting term 5 afterward!
    assert!(
        va_1.prepare_term(&PrepareTermRequest {
            group_id: "pool:m21".into(),
            epoch: 1,
            term: 5,
            leader_id: "leader-5".into(),
            from_slot: 1,
        })
        .await
        .is_err(),
        "Durable promised_term MUST NOT regress below 6!"
    );

    // 2b. Competing same-term (term 7) rival leaders -> EXACTLY ONE wins!
    let b2 = Arc::new(Barrier::new(2));
    let (ra, rb) = tokio::join!(
        {
            let b = b2.clone();
            let v = va_1.clone();
            async move {
                b.wait().await;
                v.prepare_term(&PrepareTermRequest {
                    group_id: "pool:m21".into(),
                    epoch: 1,
                    term: 7,
                    leader_id: "rival-A".into(),
                    from_slot: 1,
                })
                .await
            }
        },
        {
            let b = b2.clone();
            let v = va_2.clone();
            async move {
                b.wait().await;
                v.prepare_term(&PrepareTermRequest {
                    group_id: "pool:m21".into(),
                    epoch: 1,
                    term: 7,
                    leader_id: "rival-B".into(),
                    from_slot: 1,
                })
                .await
            }
        }
    );
    assert_eq!(
        ra.is_ok() as u8 + rb.is_ok() as u8,
        1,
        "At most ONE leader may win same-term concurrent prepare_term!"
    );

    // 3. P0 Prepare/Vote snapshot race + Concurrent higher-term slot-lock replacement race!
    let race_db = Arc::new(Database::open_mem());
    let vr_a1 = VoterNode::new("node-a", keys[0].clone(), race_db.clone());
    let vr_a2 = VoterNode::new("node-a", keys[0].clone(), race_db.clone());
    let vr_b = VoterNode::new("node-b", keys[1].clone(), Arc::new(Database::open_mem()));
    let vr_c = VoterNode::new("node-c", keys[2].clone(), Arc::new(Database::open_mem()));
    for v in [&vr_a1, &vr_b, &vr_c] {
        v.install_genesis_epoch("pool:m21", ConsensusMode::CftFastPath, old_members.clone())
            .await
            .unwrap();
    }
    let p1_a = vr_a1.prepare_term(&PrepareTermRequest { group_id: "pool:m21".into(), epoch: 1, term: 1, leader_id: "c1".into(), from_slot: 1 }).await.unwrap();
    let p1_b = vr_b.prepare_term(&PrepareTermRequest { group_id: "pool:m21".into(), epoch: 1, term: 1, leader_id: "c1".into(), from_slot: 1 }).await.unwrap();
    let p1_c = vr_c.prepare_term(&PrepareTermRequest { group_id: "pool:m21".into(), epoch: 1, term: 1, leader_id: "c1".into(), from_slot: 1 }).await.unwrap();
    let cert_1 = TermCertificate {
        group_id: "pool:m21".into(),
        epoch: 1,
        term: 1,
        leader_id: "c1".into(),
        from_slot: 1,
        mode: ConsensusMode::CftFastPath,
        promises: vec![p1_a, p1_b, p1_c],
    };

    // 3a. Prepare(term=2) vs CastVote(term=1) snapshot race on separate handles sharing `race_db`:
    //     If CastVote(term=1) succeeds, Prepare(term=2) MUST include slot 1 in accepted_locks!
    let b3 = Arc::new(Barrier::new(2));
    let vreq_t1 = VoteRequest::for_lease(1, 1, lp0.clone()).with_term(1, "c1", cert_1.clone());
    let (vote_res, prep2_res) = tokio::join!(
        {
            let b = b3.clone();
            let v = vr_a1.clone();
            let req = vreq_t1.clone();
            async move {
                b.wait().await;
                v.cast_vote(&req).await
            }
        },
        {
            let b = b3.clone();
            let v = vr_a2.clone();
            async move {
                b.wait().await;
                v.prepare_term(&PrepareTermRequest {
                    group_id: "pool:m21".into(),
                    epoch: 1,
                    term: 2,
                    leader_id: "c2".into(),
                    from_slot: 1,
                })
                .await
            }
        }
    );
    let p2_a = prep2_res.unwrap();
    if vote_res.is_ok() {
        assert!(
            p2_a.accepted_locks.iter().any(|l| l.slot == 1),
            "TermPromise(term=2) MUST NOT omit an accepted slot-1 lock that linearized before it!"
        );
    }

    // 3b. Concurrent higher-term slot-lock replacement with conflicting proposals on slot 2:
    //     First accept slot 2 at term 2 on vr_a1 (only on vr_a1; vr_b & vr_c have NO lock on slot 2),
    //     then form TermCertificate(term=3) from vr_b + vr_c + vr_d (no reported lock on slot 2!),
    //     so term 3 permits a fresh value -> race TWO conflicting proposals at term 3 on vr_a1 vs vr_a2!
    let vr_d = VoterNode::new("node-d", keys[3].clone(), Arc::new(Database::open_mem()));
    vr_d.install_genesis_epoch("pool:m21", ConsensusMode::CftFastPath, old_members.clone())
        .await
        .unwrap();
    let p2_b = vr_b.prepare_term(&PrepareTermRequest { group_id: "pool:m21".into(), epoch: 1, term: 2, leader_id: "c2".into(), from_slot: 1 }).await.unwrap();
    let p2_c = vr_c.prepare_term(&PrepareTermRequest { group_id: "pool:m21".into(), epoch: 1, term: 2, leader_id: "c2".into(), from_slot: 1 }).await.unwrap();
    let cert_2 = TermCertificate {
        group_id: "pool:m21".into(),
        epoch: 1,
        term: 2,
        leader_id: "c2".into(),
        from_slot: 1,
        mode: ConsensusMode::CftFastPath,
        promises: vec![p2_a, p2_b, p2_c],
    };
    let lp_s2_old = LeaseProposal { lease_id: "lse_s2_old".into(), ..lp0.clone() };
    let _ = vr_a1
        .cast_vote(&VoteRequest::for_lease(1, 2, lp_s2_old).with_term(2, "c2", cert_2))
        .await
        .unwrap();

    // Now prepare term 3 on vr_a1, vr_b, vr_c, vr_d, and build cert_3 from (b, c, d) which report no slot 2 lock
    let _p3_a = vr_a1.prepare_term(&PrepareTermRequest { group_id: "pool:m21".into(), epoch: 1, term: 3, leader_id: "c3".into(), from_slot: 1 }).await.unwrap();
    let p3_b = vr_b.prepare_term(&PrepareTermRequest { group_id: "pool:m21".into(), epoch: 1, term: 3, leader_id: "c3".into(), from_slot: 1 }).await.unwrap();
    let p3_c = vr_c.prepare_term(&PrepareTermRequest { group_id: "pool:m21".into(), epoch: 1, term: 3, leader_id: "c3".into(), from_slot: 1 }).await.unwrap();
    let p3_d = vr_d.prepare_term(&PrepareTermRequest { group_id: "pool:m21".into(), epoch: 1, term: 3, leader_id: "c3".into(), from_slot: 1 }).await.unwrap();
    let cert_3 = TermCertificate {
        group_id: "pool:m21".into(),
        epoch: 1,
        term: 3,
        leader_id: "c3".into(),
        from_slot: 1,
        mode: ConsensusMode::CftFastPath,
        promises: vec![p3_b, p3_c, p3_d],
    };
    let lp_s2_x = LeaseProposal { lease_id: "lse_s2_X".into(), ..lp0.clone() };
    let lp_s2_y = LeaseProposal { lease_id: "lse_s2_Y".into(), ..lp0.clone() };
    let b4 = Arc::new(Barrier::new(2));
    let (rx, ry) = tokio::join!(
        {
            let b = b4.clone();
            let v = vr_a1.clone();
            let req = VoteRequest::for_lease(1, 2, lp_s2_x.clone()).with_term(3, "c3", cert_3.clone());
            async move {
                b.wait().await;
                v.cast_vote(&req).await
            }
        },
        {
            let b = b4.clone();
            let v = vr_a2.clone();
            let req = VoteRequest::for_lease(1, 2, lp_s2_y.clone()).with_term(3, "c3", cert_3.clone());
            async move {
                b.wait().await;
                v.cast_vote(&req).await
            }
        }
    );
    assert_eq!(
        rx.is_ok() as u8 + ry.is_ok() as u8,
        1,
        "Atomic higher-term slot-lock replacement MUST allow at most ONE conflicting proposal to win!"
    );
    let (winner_vote, _) = vr_a1.query_slot_lock("pool:m21", 1, 2).await.unwrap().unwrap();
    assert_eq!(winner_vote.term, 3);
    if rx.is_ok() {
        assert_eq!(winner_vote.proposal_hash, lp_s2_x.canonical_digest());
    } else {
        assert_eq!(winner_vote.proposal_hash, lp_s2_y.canonical_digest());
    }

    // 4. P0 Dual-quorum membership partition safety + P1 Trusted genesis substitution test!
    let mut part_voters = Vec::new();
    for i in 0..8 {
        let v = VoterNode::new(format!("node-{}", ["a","b","c","d","e","f","g","h"][i]), keys[i].clone(), Arc::new(Database::open_mem()));
        if i < 5 {
            v.install_genesis_epoch("pool:m21", ConsensusMode::CftFastPath, old_members.clone())
                .await
                .unwrap();
        }
        part_voters.push(v);
    }
    let mut grp = CoordinationGroup::open_durable(
        Arc::new(Database::open_mem()),
        "pool:m21",
        ConsensusMode::CftFastPath,
        old_members.clone(),
    )
    .await
    .unwrap();
    let _ = grp.execute_takeover_catch_up("c1", 1, &part_voters[0..5]).await.unwrap();
    let cert_p1 = grp.active_term_cert.clone().unwrap();
    let m_prop = MembershipTransitionProposal::new(
        "pool:m21",
        1,
        2,
        1,
        ConsensusMode::CftFastPath,
        new_members.clone(),
    )
    .unwrap();
    let m_req = VoteRequest::for_membership(m_prop.clone()).unwrap().with_term(1, "c1", cert_p1);
    let mut m_votes = Vec::new();
    for v in &part_voters[0..3] {
        m_votes.push(v.cast_vote(&m_req).await.unwrap());
    }
    let mdec = grp.reconfigure_membership_with_quorum(&m_prop, m_votes).await.unwrap();
    let old_cfg = MembershipEpochConfig {
        mode: ConsensusMode::CftFastPath,
        members: old_members.iter().cloned().map(|m| (m.node_id.clone(), m)).collect(),
    };

    // Genesis substitution test:
    // (a) Completely uninitialized voter F receiving fake genesis + chain MUST fail with MissingTrustedGenesisAnchor!
    let fake_genesis_members = vec![gm[5].clone(), gm[6].clone(), gm[7].clone()];
    let uninit_err = part_voters[5]
        .install_membership_chain_from_genesis(
            "pool:m21",
            ConsensusMode::CftFastPath,
            fake_genesis_members.clone(),
            &[],
        )
        .await
        .unwrap_err();
    assert!(matches!(
        uninit_err.downcast_ref::<GenesisAnchorError>(),
        Some(GenesisAnchorError::MissingTrustedGenesisAnchor { .. })
    ));
    // (b) Provision trusted genesis anchor on F, G, H -> cannot overwrite with a different digest,
    //     and substituted fake genesis chain MUST fail with AnchorMismatch!
    for v in &part_voters[5..8] {
        v.set_trusted_genesis_anchor("pool:m21", genesis_digest.clone())
            .await
            .unwrap();
    }
    let fake_digest = hash_genesis_config("pool:m21", ConsensusMode::CftFastPath, &fake_genesis_members).unwrap();
    assert!(matches!(
        part_voters[5]
            .set_trusted_genesis_anchor("pool:m21", fake_digest)
            .await
            .unwrap_err()
            .downcast_ref::<GenesisAnchorError>(),
        Some(GenesisAnchorError::AnchorMismatch { .. })
    ));
    assert!(matches!(
        part_voters[5]
            .install_membership_chain_from_genesis(
                "pool:m21",
                ConsensusMode::CftFastPath,
                fake_genesis_members,
                &[],
            )
            .await
            .unwrap_err()
            .downcast_ref::<GenesisAnchorError>(),
        Some(GenesisAnchorError::AnchorMismatch { .. })
    ));
    // Bootstrap new members F, G, H with the genuine trusted genesis anchor + verified transition!
    for v in &part_voters[5..8] {
        v.install_membership_chain_from_genesis(
            "pool:m21",
            ConsensusMode::CftFastPath,
            old_members.clone(),
            &[mdec.clone()],
        )
        .await
        .unwrap();
    }

    // Partition test: isolate old-config quorum (C, D, E unreachable -> only A, B + F, G, H reachable).
    // Even though 5/5 new members installed epoch 2, only 2/5 old members (A, B) are fenced (< quorum 3) ->
    // `activate_membership_transition` MUST FAIL CLOSED so C, D, E cannot split-brain!
    let reachable_without_old_quorum = vec![
        part_voters[0].clone(),
        part_voters[1].clone(),
        part_voters[5].clone(),
        part_voters[6].clone(),
        part_voters[7].clone(),
    ];
    assert!(
        grp.activate_membership_transition(&mdec, &old_cfg, &reachable_without_old_quorum)
            .await
            .is_err(),
        "Activation MUST fail closed when fewer than Q(C_old) old voters are durably fenced!"
    );

    // Once C reconnects (3/5 old voters A,B,C fenced + 5/5 new voters installed):
    // activation SUCCEEDS, reports D & E in `pending_removed_fence_nodes`, AND isolated (C,D,E)
    // can NO LONGER form an epoch-1 quorum because C is durably fenced at epoch 2!
    let reachable_with_old_quorum = vec![
        part_voters[0].clone(),
        part_voters[1].clone(),
        part_voters[2].clone(),
        part_voters[5].clone(),
        part_voters[6].clone(),
        part_voters[7].clone(),
    ];
    let pending_removed = grp
        .activate_membership_transition(&mdec, &old_cfg, &reachable_with_old_quorum)
        .await
        .unwrap();
    assert_eq!(pending_removed, vec!["node-d".to_string(), "node-e".to_string()]);
    assert!(
        part_voters[2]
            .prepare_term(&PrepareTermRequest {
                group_id: "pool:m21".into(),
                epoch: 1,
                term: 9,
                leader_id: "split-brain-old".into(),
                from_slot: 1,
            })
            .await
            .is_err(),
        "Fenced old voter C MUST reject epoch-1 requests, preventing C+D+E split-brain!"
    );

    // 5. P1 Strict accepted-lock history validation: wrong epoch, duplicate slot, forged embedded vote!
    let mut bad_epoch_cert = cert_3.clone();
    let bad_lock = AcceptedSlotLock {
        epoch: 99, // Wrong epoch!
        slot: 1,
        accepted_term: 1,
        proposal_hash: lp0.canonical_digest(),
        proposal: SlotProposal::Lease(lp0.clone()),
        vote: sign_vote_raw_in_term("pool:m21", 99, 1, 1, &lp0.canonical_digest(), "node-b", &keys[1]).unwrap(),
    };
    bad_epoch_cert.promises[0].accepted_locks = vec![bad_lock.clone()];
    let bp = nexus_io::mesh::consensus::canonical_promise_payload(
        &bad_epoch_cert.promises[0].group_id,
        bad_epoch_cert.promises[0].epoch,
        bad_epoch_cert.promises[0].term,
        &bad_epoch_cert.promises[0].leader_id,
        bad_epoch_cert.promises[0].from_slot,
        &bad_epoch_cert.promises[0].voter_node_id,
        bad_epoch_cert.promises[0].min_active_epoch,
        &bad_epoch_cert.promises[0].accepted_locks,
    );
    bad_epoch_cert.promises[0].signature = nexus_db::auth::ed25519_sign(&keys[1], &bp).unwrap();
    assert!(
        verify_term_certificate_and_adoption(&bad_epoch_cert, &old_cfg, 1).is_err(),
        "Wrong-epoch accepted lock MUST fail the entire promise!"
    );

    // Duplicate slot lock in same promise -> REJECTED!
    let mut dup_slot_cert = cert_3.clone();
    let valid_lock_b = AcceptedSlotLock {
        epoch: 1,
        slot: 1,
        accepted_term: 1,
        proposal_hash: lp0.canonical_digest(),
        proposal: SlotProposal::Lease(lp0.clone()),
        vote: sign_vote_raw_in_term("pool:m21", 1, 1, 1, &lp0.canonical_digest(), "node-b", &keys[1]).unwrap(),
    };
    dup_slot_cert.promises[0].accepted_locks = vec![valid_lock_b.clone(), valid_lock_b.clone()];
    let dp = nexus_io::mesh::consensus::canonical_promise_payload(
        &dup_slot_cert.promises[0].group_id,
        dup_slot_cert.promises[0].epoch,
        dup_slot_cert.promises[0].term,
        &dup_slot_cert.promises[0].leader_id,
        dup_slot_cert.promises[0].from_slot,
        &dup_slot_cert.promises[0].voter_node_id,
        dup_slot_cert.promises[0].min_active_epoch,
        &dup_slot_cert.promises[0].accepted_locks,
    );
    dup_slot_cert.promises[0].signature = nexus_db::auth::ed25519_sign(&keys[1], &dp).unwrap();
    assert!(
        verify_term_certificate_and_adoption(&dup_slot_cert, &old_cfg, 1).is_err(),
        "Duplicate accepted lock for same slot in one promise MUST fail closed!"
    );

    // Forged embedded SignedVote signature inside an otherwise validly signed TermPromise -> REJECTED!
    let mut forged_vote_cert = cert_3.clone();
    let mut bad_sig_lock = valid_lock_b;
    bad_sig_lock.vote.signature = "AAAA_FORGED_SIG".into();
    forged_vote_cert.promises[0].accepted_locks = vec![bad_sig_lock];
    let fp = nexus_io::mesh::consensus::canonical_promise_payload(
        &forged_vote_cert.promises[0].group_id,
        forged_vote_cert.promises[0].epoch,
        forged_vote_cert.promises[0].term,
        &forged_vote_cert.promises[0].leader_id,
        forged_vote_cert.promises[0].from_slot,
        &forged_vote_cert.promises[0].voter_node_id,
        forged_vote_cert.promises[0].min_active_epoch,
        &forged_vote_cert.promises[0].accepted_locks,
    );
    forged_vote_cert.promises[0].signature = nexus_db::auth::ed25519_sign(&keys[1], &fp).unwrap();
    assert!(
        verify_term_certificate_and_adoption(&forged_vote_cert, &old_cfg, 1).is_err(),
        "Forged embedded SignedVote signature in AcceptedSlotLock MUST fail closed!"
    );

    // 6. Milestone 2.2: Crash after membership vote & durable barrier acceptance ->
    //    Reopened on-disk voter MUST still reject old-epoch S+1!
    let barrier_dir = std::env::temp_dir().join(format!("nexus_m22_barrier_{}", uuid::Uuid::new_v4().simple()));
    let lp_s2_after_m = LeaseProposal {
        lease_id: "lse_post_transition_s2".into(),
        ..lp0.clone()
    };
    {
        let bdb = Arc::new(Database::init_in(&barrier_dir).await);
        let vb_a = VoterNode::new("node-a", keys[0].clone(), bdb);
        let vb_b = VoterNode::new("node-b", keys[1].clone(), Arc::new(Database::open_mem()));
        let vb_c = VoterNode::new("node-c", keys[2].clone(), Arc::new(Database::open_mem()));
        for v in [&vb_a, &vb_b, &vb_c] {
            v.install_genesis_epoch("pool:m22", ConsensusMode::CftFastPath, old_members[0..3].to_vec())
                .await
                .unwrap();
        }
        let pb_a = vb_a.prepare_term(&PrepareTermRequest { group_id: "pool:m22".into(), epoch: 1, term: 1, leader_id: "c1".into(), from_slot: 1 }).await.unwrap();
        let pb_b = vb_b.prepare_term(&PrepareTermRequest { group_id: "pool:m22".into(), epoch: 1, term: 1, leader_id: "c1".into(), from_slot: 1 }).await.unwrap();
        let cert_b1 = TermCertificate {
            group_id: "pool:m22".into(),
            epoch: 1,
            term: 1,
            leader_id: "c1".into(),
            from_slot: 1,
            mode: ConsensusMode::CftFastPath,
            promises: vec![pb_a, pb_b],
        };
        let mb_prop = MembershipTransitionProposal::new(
            "pool:m22",
            1,
            2,
            1,
            ConsensusMode::CftFastPath,
            vec![gm[0].clone(), gm[1].clone()],
        )
        .unwrap();
        // Accept membership transition at slot 1 -> atomically persists lock + durable barrier `epoch_barriers[1] = 1`!
        let _ = vb_a
            .cast_vote(&VoteRequest::for_membership(mb_prop).unwrap().with_term(1, "c1", cert_b1.clone()))
            .await
            .unwrap();
        // Drop & reopen voter from disk to prove barrier survives crash/restart!
        drop(vb_a);
        let bdb_reopened = Arc::new(Database::init_in(&barrier_dir).await);
        let vb_a_reopened = VoterNode::new("node-a", keys[0].clone(), bdb_reopened);
        let post_s2_req = VoteRequest::for_lease(1, 2, LeaseProposal { group_id: "pool:m22".into(), ..lp_s2_after_m.clone() })
            .with_term(1, "c1", cert_b1);
        assert!(
            vb_a_reopened.cast_vote(&post_s2_req).await.is_err(),
            "Reopened voter MUST still enforce durable old-epoch barrier and reject slot S+1!"
        );
    }
    let _ = std::fs::remove_dir_all(&barrier_dir);

    // 7. Milestone 2.2: Unresolved old-epoch S+1 lock preservation, receipt validation,
    //    activation fail-closed, AND barrier-synchronized S+1 race during activation!
    let unres_db_dir = std::env::temp_dir().join(format!("nexus_m22_unres_{}", uuid::Uuid::new_v4().simple()));
    {
        let udb_c = Arc::new(Database::init_in(&unres_db_dir).await);
        let vu_a = VoterNode::new("node-a", keys[0].clone(), Arc::new(Database::open_mem()));
        let vu_b = VoterNode::new("node-b", keys[1].clone(), Arc::new(Database::open_mem()));
        let vu_c = VoterNode::new("node-c", keys[2].clone(), udb_c.clone());
        let u_old_members = old_members[0..3].to_vec();
        let u_old_cfg = MembershipEpochConfig {
            mode: ConsensusMode::CftFastPath,
            members: u_old_members.iter().cloned().map(|m| (m.node_id.clone(), m)).collect(),
        };
        for v in [&vu_a, &vu_b, &vu_c] {
            v.install_genesis_epoch("pool:m22-u", ConsensusMode::CftFastPath, u_old_members.clone())
                .await
                .unwrap();
        }
        let pu_a = vu_a.prepare_term(&PrepareTermRequest { group_id: "pool:m22-u".into(), epoch: 1, term: 1, leader_id: "c1".into(), from_slot: 1 }).await.unwrap();
        let pu_b = vu_b.prepare_term(&PrepareTermRequest { group_id: "pool:m22-u".into(), epoch: 1, term: 1, leader_id: "c1".into(), from_slot: 1 }).await.unwrap();
        let pu_c = vu_c.prepare_term(&PrepareTermRequest { group_id: "pool:m22-u".into(), epoch: 1, term: 1, leader_id: "c1".into(), from_slot: 1 }).await.unwrap();
        let cert_u1 = TermCertificate {
            group_id: "pool:m22-u".into(),
            epoch: 1,
            term: 1,
            leader_id: "c1".into(),
            from_slot: 1,
            mode: ConsensusMode::CftFastPath,
            promises: vec![pu_a, pu_b, pu_c],
        };
        // A & B accept membership transition at slot 1; meanwhile C (before learning of slot 1)
        // accepts an old-epoch lease vote at slot 2 (S+1)!
        let mu_prop = MembershipTransitionProposal::new(
            "pool:m22-u",
            1,
            2,
            1,
            ConsensusMode::CftFastPath,
            vec![gm[0].clone(), gm[1].clone()],
        )
        .unwrap();
        let mu_req = VoteRequest::for_membership(mu_prop.clone()).unwrap().with_term(1, "c1", cert_u1.clone());
        let mv_a = vu_a.cast_vote(&mu_req).await.unwrap();
        let mv_b = vu_b.cast_vote(&mu_req).await.unwrap();
        let mut u_grp = CoordinationGroup::open_durable(
            Arc::new(Database::open_mem()),
            "pool:m22-u",
            ConsensusMode::CftFastPath,
            u_old_members.clone(),
        )
        .await
        .unwrap();
        let mu_dec = u_grp.reconfigure_membership_with_quorum(&mu_prop, vec![mv_a, mv_b]).await.unwrap();

        let s2_prop = LeaseProposal {
            group_id: "pool:m22-u".into(),
            lease_id: "lse_unresolved_s2".into(),
            ..lp0.clone()
        };
        let _ = vu_c
            .cast_vote(&VoteRequest::for_lease(1, 2, s2_prop.clone()).with_term(1, "c1", cert_u1.clone()))
            .await
            .unwrap();

        // Install transition at slot 1 on C -> receipt MUST preserve the validated slot-2 lock,
        // NOT advance min_active_epoch to 2, AND install the durable barrier for slot > 1!
        let receipt_c = vu_c.install_membership_epoch(&mu_dec, &u_old_cfg).await.unwrap();
        assert_eq!(receipt_c.min_active_epoch, 1, "Voter with unresolved S+1 lock must not activate epoch 2!");
        assert_eq!(receipt_c.post_transition_old_locks.len(), 1);
        assert_eq!(receipt_c.post_transition_old_locks[0].slot, 2);
        assert_eq!(receipt_c.post_transition_old_locks[0].proposal_hash, s2_prop.canonical_digest());

        // Activation across (A, B, C) MUST FAIL CLOSED because C reported an unresolved S+1 lock!
        assert!(
            u_grp
                .activate_membership_transition(&mu_dec, &u_old_cfg, &[vu_a, vu_b, vu_c.clone()])
                .await
                .is_err(),
            "activate_membership_transition MUST fail closed when any old voter has an unresolved S+1 lock!"
        );

        // Restart voter C from disk -> unresolved slot-2 lock is STILL preserved for recovery,
        // AND further old-epoch slot-3 votes are fenced by the durable barrier!
        drop(vu_c);
        drop(udb_c);
        let udb_c_reopened = Arc::new(Database::init_in(&unres_db_dir).await);
        let vu_c_reopened = VoterNode::new("node-c", keys[2].clone(), udb_c_reopened);
        let (preserved_vote, preserved_prop) = vu_c_reopened
            .query_slot_lock("pool:m22-u", 1, 2)
            .await
            .unwrap()
            .expect("Unresolved S+1 lock MUST be preserved across restart for recovery!");
        assert_eq!(preserved_vote.proposal_hash, s2_prop.canonical_digest());
        assert_eq!(preserved_prop, Some(SlotProposal::Lease(s2_prop)));
        assert!(
            vu_c_reopened
                .cast_vote(
                    &VoteRequest::for_lease(1, 3, LeaseProposal { group_id: "pool:m22-u".into(), lease_id: "lse_s3".into(), ..lp0 })
                        .with_term(1, "c1", cert_u1)
                )
                .await
                .is_err(),
            "Durable barrier on C MUST reject further old-epoch votes (slot 3) after restart!"
        );
    }
    let _ = std::fs::remove_dir_all(&unres_db_dir);
}
