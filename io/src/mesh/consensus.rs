//! Nexus Scoped Hybrid Consensus Foundation (Durable Proposal+Vote Locks, Autonomous Recovery & Authenticated Fencing)
//!
//! Maturity & Scope (Explicit):
//! - **`CftFastPath` (`2f + 1` quorum — `experimental`):** Durable per-voter locks persist both
//!   the signed vote and canonical `LeaseProposal` atomically before signing, enabling an
//!   independent standby coordinator to recover and commit a quorum decision without the crashed
//!   coordinator restarting. Both normal commitment and recovery share one atomic slot-commit
//!   transaction (`sys_mesh_decision_log` + `sys_mesh_membership`).
//! - **`BftSigned` (`3f + 1` quorum — `prototype`):** Signed `3f + 1` quorum thresholds and
//!   cryptographic `EquivocationProof` detection (full multi-round Byzantine view-change pending).

use anyhow::{anyhow, Result};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::db::{is_already_exists_error, Database};

const FENCE_STRIPE_COUNT: usize = 64;

fn fence_stripe_idx(key: &str) -> usize {
    let h = blake3::hash(key.as_bytes());
    let b = h.as_bytes();
    (u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize) % FENCE_STRIPE_COUNT
}

static FENCE_STRIPES: Lazy<Vec<tokio::sync::Mutex<()>>> =
    Lazy::new(|| (0..FENCE_STRIPE_COUNT).map(|_| tokio::sync::Mutex::new(())).collect());

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsensusMode {
    /// Model A: Crash-Fault Tolerant quorum (`quorum = n / 2 + 1`) backed by durable vote-locks.
    CftFastPath,
    /// Model B: Signed `3f + 1` quorum (`quorum = (2 * n) / 3 + 1`) + equivocation proof detection.
    BftSigned,
}

impl ConsensusMode {
    pub fn quorum_size(self, total_members: usize) -> usize {
        if total_members == 0 {
            return 1;
        }
        match self {
            Self::CftFastPath => (total_members / 2) + 1,
            Self::BftSigned => ((2 * total_members) / 3) + 1,
        }
    }

    pub fn canonical_tag(self) -> &'static str {
        match self {
            Self::CftFastPath => "cft_fast_path",
            Self::BftSigned => "bft_signed",
        }
    }
}

/// Authorized coordination group member binding node, identity, organization, and public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMember {
    pub node_id: String,
    pub identity_id: String,
    pub org_id: String,
    pub ed25519_pubkey: String,
}

/// Canonical source of lease authority & validity fields persisted alongside durable voter locks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseProposal {
    pub group_id: String,
    pub lease_id: String,
    pub resource_key: String,
    pub holder_node_id: String,
    pub workload_id: String,
    pub fencing_epoch: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

impl LeaseProposal {
    /// Single canonical length-prefixed encoding (`NEXUS-LEASE-PROPOSAL-v2`).
    pub fn canonical_digest(&self) -> String {
        hash_lease_proposal(
            &self.group_id,
            &self.lease_id,
            &self.resource_key,
            &self.holder_node_id,
            &self.workload_id,
            self.fencing_epoch,
            self.issued_at_ms,
            self.expires_at_ms,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteRequest {
    pub group_id: String,
    pub epoch: u64,
    pub slot: u64,
    pub proposal_hash: String,
    /// Canonical proposal payload persisted atomically with the voter's durable lock for recovery.
    #[serde(default)]
    pub proposal: Option<LeaseProposal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedVote {
    pub group_id: String,
    pub epoch: u64,
    pub slot: u64,
    pub proposal_hash: String,
    pub voter_node_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumCertificate {
    pub group_id: String,
    pub epoch: u64,
    pub slot: u64,
    pub proposal_hash: String,
    pub mode: ConsensusMode,
    pub votes: Vec<SignedVote>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquivocationProof {
    pub group_id: String,
    pub epoch: u64,
    pub slot: u64,
    pub voter_node_id: String,
    pub vote_a: SignedVote,
    pub vote_b: SignedVote,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FencedLease {
    pub lease_id: String,
    pub group_id: String,
    pub resource_key: String,
    pub holder_node_id: String,
    pub workload_id: String,
    pub fencing_epoch: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub qc: QuorumCertificate,
}

impl FencedLease {
    pub fn proposal(&self) -> LeaseProposal {
        LeaseProposal {
            group_id: self.group_id.clone(),
            lease_id: self.lease_id.clone(),
            resource_key: self.resource_key.clone(),
            holder_node_id: self.holder_node_id.clone(),
            workload_id: self.workload_id.clone(),
            fencing_epoch: self.fencing_epoch,
            issued_at_ms: self.issued_at_ms,
            expires_at_ms: self.expires_at_ms,
        }
    }

    pub fn canonical_digest(&self) -> String {
        self.proposal().canonical_digest()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DurableVoterLock {
    lock_key: String,
    group_id: String,
    epoch: u64,
    slot: u64,
    proposal_hash: String,
    #[serde(default)]
    proposal: Option<LeaseProposal>,
    voter_node_id: String,
    signature: String,
    locked_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DurableMembershipRecord {
    group_id: String,
    mode: ConsensusMode,
    membership_epoch: u64,
    next_slot: u64,
    members: Vec<GroupMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AcceptedFenceRecord {
    resource_key: String,
    holder_node_id: String,
    highest_epoch: u64,
    expires_at_ms: u64,
    lease_id: String,
    lease_digest: String,
    updated_at_ms: u64,
}

fn push_len_prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
}

pub fn canonical_vote_payload(
    group_id: &str,
    epoch: u64,
    slot: u64,
    proposal_hash: &str,
    voter_node_id: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(b"NEXUS-CONSENSUS-VOTE-v1");
    for field in [group_id.as_bytes(), proposal_hash.as_bytes(), voter_node_id.as_bytes()] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field);
    }
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&slot.to_be_bytes());
    out
}

pub fn sign_vote_raw(
    group_id: &str,
    epoch: u64,
    slot: u64,
    proposal_hash: &str,
    voter_node_id: &str,
    voter_sk_b64: &str,
) -> Result<SignedVote> {
    let payload = canonical_vote_payload(group_id, epoch, slot, proposal_hash, voter_node_id);
    let sig = nexus_db::auth::ed25519_sign(voter_sk_b64, &payload)?;
    Ok(SignedVote {
        group_id: group_id.to_string(),
        epoch,
        slot,
        proposal_hash: proposal_hash.to_string(),
        voter_node_id: voter_node_id.to_string(),
        signature: sig,
    })
}

/// Single canonical length-prefixed lease digest (`NEXUS-LEASE-PROPOSAL-v2`).
#[allow(clippy::too_many_arguments)]
pub fn hash_lease_proposal(
    group_id: &str,
    lease_id: &str,
    resource_key: &str,
    holder_node_id: &str,
    workload_id: &str,
    fencing_epoch: u64,
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"NEXUS-LEASE-PROPOSAL-v2");
    for field in [
        group_id.as_bytes(),
        lease_id.as_bytes(),
        resource_key.as_bytes(),
        holder_node_id.as_bytes(),
        workload_id.as_bytes(),
    ] {
        push_len_prefixed(&mut hasher, field);
    }
    hasher.update(&fencing_epoch.to_be_bytes());
    hasher.update(&issued_at_ms.to_be_bytes());
    hasher.update(&expires_at_ms.to_be_bytes());
    hasher.finalize().to_hex().to_string()
}

pub fn hash_membership_change(
    group_id: &str,
    next_epoch: u64,
    mode: ConsensusMode,
    new_members: &[GroupMember],
) -> Result<String> {
    let mut sorted = new_members.to_vec();
    sorted.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    let mut seen = HashSet::new();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"NEXUS-MEMBERSHIP-CHANGE-v2");
    push_len_prefixed(&mut hasher, group_id.as_bytes());
    hasher.update(&next_epoch.to_be_bytes());
    push_len_prefixed(&mut hasher, mode.canonical_tag().as_bytes());
    hasher.update(&(sorted.len() as u32).to_be_bytes());
    for m in &sorted {
        if !seen.insert(m.node_id.as_str()) {
            anyhow::bail!("Duplicate node_id '{}' in membership transition", m.node_id);
        }
        push_len_prefixed(&mut hasher, m.node_id.as_bytes());
        push_len_prefixed(&mut hasher, m.identity_id.as_bytes());
        push_len_prefixed(&mut hasher, m.org_id.as_bytes());
        push_len_prefixed(&mut hasher, m.ed25519_pubkey.as_bytes());
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn slot_decision_key(group_id: &str, epoch: u64, slot: u64) -> String {
    format!(
        "{}_e{}_s{}",
        &blake3::hash(group_id.as_bytes()).to_hex().as_str()[..16],
        epoch,
        slot
    )
}

/// Independent durable voter node backed by its own `nexus-db` instance.
#[derive(Clone)]
pub struct VoterNode {
    pub node_id: String,
    pub ed25519_sk_b64: String,
    db: Arc<Database>,
}

impl VoterNode {
    pub fn new(node_id: impl Into<String>, ed25519_sk_b64: impl Into<String>, db: Arc<Database>) -> Self {
        Self {
            node_id: node_id.into(),
            ed25519_sk_b64: ed25519_sk_b64.into(),
            db,
        }
    }

    pub async fn ensure_tables(&self) -> Result<()> {
        let _ = self
            .db
            .client
            .query("DEFINE TABLE IF NOT EXISTS sys_mesh_voter_lock SCHEMALESS;")
            .await;
        Ok(())
    }

    fn slot_lock_key(&self, group_id: &str, epoch: u64, slot: u64) -> String {
        format!(
            "{}_{}_{}_{}",
            &blake3::hash(group_id.as_bytes()).to_hex().as_str()[..12],
            epoch,
            slot,
            self.node_id
        )
    }

    /// Query this voter's durable lock (both `SignedVote` and canonical `Option<LeaseProposal>`).
    pub async fn query_slot_lock(
        &self,
        group_id: &str,
        epoch: u64,
        slot: u64,
    ) -> Result<Option<(SignedVote, Option<LeaseProposal>)>> {
        self.ensure_tables().await?;
        let lock_key = self.slot_lock_key(group_id, epoch, slot);
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_mesh_voter_lock', $id)")
            .bind(("id", lock_key))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        Ok(rows
            .first()
            .and_then(|v| serde_json::from_value::<DurableVoterLock>(v.clone()).ok())
            .map(|existing| {
                (
                    SignedVote {
                        group_id: existing.group_id,
                        epoch: existing.epoch,
                        slot: existing.slot,
                        proposal_hash: existing.proposal_hash,
                        voter_node_id: existing.voter_node_id,
                        signature: existing.signature,
                    },
                    existing.proposal,
                )
            }))
    }

    /// Verify proposal digest (if supplied), atomically persist durable lock + proposal BEFORE
    /// returning signature, and never overwrite an existing lock!
    pub async fn cast_vote(&self, req: &VoteRequest) -> Result<SignedVote> {
        if let Some(ref prop) = req.proposal {
            if prop.group_id != req.group_id {
                anyhow::bail!(
                    "Proposal group_id '{}' does not match vote group_id '{}'",
                    prop.group_id,
                    req.group_id
                );
            }
            let computed = prop.canonical_digest();
            if computed != req.proposal_hash {
                anyhow::bail!(
                    "Proposal payload digest '{}' does not match claimed proposal_hash '{}'",
                    computed,
                    req.proposal_hash
                );
            }
        }

        self.ensure_tables().await?;
        let lock_key = self.slot_lock_key(&req.group_id, req.epoch, req.slot);
        let vote = sign_vote_raw(
            &req.group_id,
            req.epoch,
            req.slot,
            &req.proposal_hash,
            &self.node_id,
            &self.ed25519_sk_b64,
        )?;
        let lock_rec = DurableVoterLock {
            lock_key: lock_key.clone(),
            group_id: req.group_id.clone(),
            epoch: req.epoch,
            slot: req.slot,
            proposal_hash: req.proposal_hash.clone(),
            proposal: req.proposal.clone(),
            voter_node_id: self.node_id.clone(),
            signature: vote.signature.clone(),
            locked_at_ms: now_ms(),
        };
        let val = serde_json::to_value(&lock_rec)?;

        let create_res = self
            .db
            .client
            .query("CREATE type::record('sys_mesh_voter_lock', $id) CONTENT $l;")
            .bind(("id", lock_key))
            .bind(("l", val))
            .await;

        match create_res {
            Ok(resp) => match resp.check() {
                Ok(_) => return Ok(vote),
                Err(e) if is_already_exists_error(&e) => {}
                Err(e) => return Err(anyhow!("Failed to persist voter lock: {}", e)),
            },
            Err(e) if is_already_exists_error(&e) => {}
            Err(e) => return Err(anyhow!("Database error persisting voter lock: {}", e)),
        }

        // Existing lock found: require BOTH proposal_hash and canonical proposal contents to match!
        let (existing_vote, existing_prop) = self
            .query_slot_lock(&req.group_id, req.epoch, req.slot)
            .await?
            .ok_or_else(|| anyhow!("Voter lock reported existing but could not be read back"))?;

        if existing_vote.proposal_hash == req.proposal_hash {
            if let (Some(ref ep), Some(ref rp)) = (&existing_prop, &req.proposal) {
                if ep != rp {
                    anyhow::bail!(
                        "Conflicting proposal payload on node '{}' for matching hash '{}'",
                        self.node_id,
                        req.proposal_hash
                    );
                }
            }
            return Ok(existing_vote);
        }

        anyhow::bail!(
            "Durable vote-lock conflict on node '{}' for ({}, epoch={}, slot={}): already locked on '{}', refusing '{}'",
            self.node_id,
            req.group_id,
            req.epoch,
            req.slot,
            existing_vote.proposal_hash,
            req.proposal_hash
        )
    }
}

/// Authenticated resource-boundary fencing guard enforced directly at the protected resource.
#[derive(Clone)]
pub struct FencedResourceGuard {
    db: Arc<Database>,
    local_accepted: Arc<RwLock<HashMap<String, AcceptedFenceRecord>>>,
}

impl FencedResourceGuard {
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            local_accepted: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn ensure_tables(&self) -> Result<()> {
        let _ = self
            .db
            .client
            .query("DEFINE TABLE IF NOT EXISTS sys_mesh_resource_fence SCHEMALESS;")
            .await;
        Ok(())
    }

    /// Production entrypoint: uses the trusted resource host's own wall clock (`now_ms()`).
    pub async fn install_lease_now(
        &self,
        lease: &FencedLease,
        group: &CoordinationGroup,
    ) -> Result<u64> {
        self.install_lease_internal(lease, group, now_ms()).await
    }

    /// Production hot-path entrypoint: uses the trusted resource host's own wall clock (`now_ms()`).
    pub async fn authorize_local_exec_now(
        &self,
        resource_key: &str,
        holder_node_id: &str,
        fencing_epoch: u64,
    ) -> Result<u64> {
        self.authorize_local_exec_internal(resource_key, holder_node_id, fencing_epoch, now_ms())
            .await
    }

    /// Deterministic clock entrypoint strictly for tests (`*_for_test` naming prevents accidental production use).
    pub async fn install_lease_at_for_test(
        &self,
        lease: &FencedLease,
        group: &CoordinationGroup,
        now: u64,
    ) -> Result<u64> {
        self.install_lease_internal(lease, group, now).await
    }

    /// Deterministic clock entrypoint strictly for tests.
    pub async fn authorize_local_exec_at_for_test(
        &self,
        resource_key: &str,
        holder_node_id: &str,
        fencing_epoch: u64,
        now: u64,
    ) -> Result<u64> {
        self.authorize_local_exec_internal(resource_key, holder_node_id, fencing_epoch, now)
            .await
    }

    async fn install_lease_internal(
        &self,
        lease: &FencedLease,
        group: &CoordinationGroup,
        now: u64,
    ) -> Result<u64> {
        if lease.group_id != group.group_id {
            anyhow::bail!(
                "Lease group_id '{}' does not match authorized group '{}'",
                lease.group_id,
                group.group_id
            );
        }
        if lease.fencing_epoch == 0 {
            anyhow::bail!("Fencing epoch must be >= 1");
        }
        if lease.expires_at_ms <= lease.issued_at_ms {
            anyhow::bail!("Lease '{}' has invalid validity interval", lease.lease_id);
        }
        if lease.expires_at_ms - lease.issued_at_ms > group.max_lease_ttl_ms {
            anyhow::bail!(
                "Lease '{}' duration ({}ms) exceeds group max_lease_ttl_ms ({}ms)",
                lease.lease_id,
                lease.expires_at_ms - lease.issued_at_ms,
                group.max_lease_ttl_ms
            );
        }
        if now >= lease.expires_at_ms {
            anyhow::bail!("Cannot install expired lease '{}' at resource boundary", lease.lease_id);
        }
        group.verify_qc(&lease.qc)?;
        let expected_digest = lease.canonical_digest();
        if lease.qc.proposal_hash != expected_digest {
            anyhow::bail!("Lease QC proposal_hash does not match complete canonical lease digest");
        }

        let _guard = FENCE_STRIPES[fence_stripe_idx(&lease.resource_key)].lock().await;
        self.ensure_tables().await?;
        let key = blake3::hash(lease.resource_key.as_bytes()).to_hex().to_string();

        let rec = AcceptedFenceRecord {
            resource_key: lease.resource_key.clone(),
            holder_node_id: lease.holder_node_id.clone(),
            highest_epoch: lease.fencing_epoch,
            expires_at_ms: lease.expires_at_ms,
            lease_id: lease.lease_id.clone(),
            lease_digest: expected_digest.clone(),
            updated_at_ms: now,
        };
        let rec_val = serde_json::to_value(&rec)?;

        let create_res = self
            .db
            .client
            .query("CREATE type::record('sys_mesh_resource_fence', $id) CONTENT $r;")
            .bind(("id", key.clone()))
            .bind(("r", rec_val))
            .await;

        let created = match create_res {
            Ok(resp) => match resp.check() {
                Ok(_) => true,
                Err(e) if is_already_exists_error(&e) => false,
                Err(e) => return Err(anyhow!("Failed to initialize resource fence: {}", e)),
            },
            Err(e) if is_already_exists_error(&e) => false,
            Err(e) => return Err(anyhow!("Database error initializing resource fence: {}", e)),
        };

        if !created {
            let mut upd = self
                .db
                .client
                .query(
                    "UPDATE type::record('sys_mesh_resource_fence', $id) \
                     SET holder_node_id = $holder, highest_epoch = $ep, expires_at_ms = $exp, lease_id = $lid, lease_digest = $dig, updated_at_ms = $now \
                     WHERE highest_epoch < $ep OR (highest_epoch == $ep AND lease_id == $lid AND lease_digest == $dig);",
                )
                .bind(("id", key))
                .bind(("holder", lease.holder_node_id.clone()))
                .bind(("ep", lease.fencing_epoch))
                .bind(("exp", lease.expires_at_ms))
                .bind(("lid", lease.lease_id.clone()))
                .bind(("dig", expected_digest))
                .bind(("now", now))
                .await?;
            let updated_rows: Vec<serde_json::Value> = upd.take(0).unwrap_or_default();
            if updated_rows.is_empty() {
                anyhow::bail!(
                    "Resource boundary rejected stale or conflicting lease '{}' (epoch={}) for '{}'",
                    lease.lease_id,
                    lease.fencing_epoch,
                    lease.resource_key
                );
            }
        }

        if let Ok(mut map) = self.local_accepted.write() {
            map.insert(lease.resource_key.clone(), rec);
        }
        Ok(lease.fencing_epoch)
    }

    async fn authorize_local_exec_internal(
        &self,
        resource_key: &str,
        holder_node_id: &str,
        fencing_epoch: u64,
        now: u64,
    ) -> Result<u64> {
        if let Ok(map) = self.local_accepted.read() {
            if let Some(rec) = map.get(resource_key) {
                if fencing_epoch < rec.highest_epoch {
                    anyhow::bail!(
                        "Stale fencing_epoch {} rejected on hot path (highest accepted: {})",
                        fencing_epoch,
                        rec.highest_epoch
                    );
                }
                if fencing_epoch != rec.highest_epoch || rec.holder_node_id != holder_node_id {
                    anyhow::bail!(
                        "Unauthorized holder '{}' / epoch {} (installed: '{}' @ {})",
                        holder_node_id,
                        fencing_epoch,
                        rec.holder_node_id,
                        rec.highest_epoch
                    );
                }
                if now >= rec.expires_at_ms {
                    anyhow::bail!("Installed lease '{}' has expired", rec.lease_id);
                }
                return Ok(rec.highest_epoch);
            }
        }
        self.ensure_tables().await?;
        let key = blake3::hash(resource_key.as_bytes()).to_hex().to_string();
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_mesh_resource_fence', $id)")
            .bind(("id", key))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let rec: AcceptedFenceRecord = rows
            .first()
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .ok_or_else(|| anyhow!("No authenticated lease installed for '{}'", resource_key))?;
        if let Ok(mut map) = self.local_accepted.write() {
            map.insert(resource_key.to_string(), rec.clone());
        }
        if fencing_epoch != rec.highest_epoch || rec.holder_node_id != holder_node_id || now >= rec.expires_at_ms {
            anyhow::bail!(
                "Resource boundary rejected execution by '{}' at epoch {} (installed: '{}' @ {})",
                holder_node_id,
                fencing_epoch,
                rec.holder_node_id,
                rec.highest_epoch
            );
        }
        Ok(rec.highest_epoch)
    }
}

/// Independent partitioned coordination group with durable slot-commit arbitration & autonomous recovery.
#[derive(Clone)]
pub struct CoordinationGroup {
    pub group_id: String,
    pub mode: ConsensusMode,
    pub membership_epoch: u64,
    pub next_slot: u64,
    pub max_lease_ttl_ms: u64,
    pub members: HashMap<String, GroupMember>,
    pub active_leases: HashMap<String, FencedLease>,
    pub max_fencing_epoch: HashMap<String, u64>,
    seen_votes: HashMap<(u64, u64, String), SignedVote>,
    pub equivocations: Vec<EquivocationProof>,
    db: Option<Arc<Database>>,
}

impl CoordinationGroup {
    pub fn new(group_id: impl Into<String>, mode: ConsensusMode, members: Vec<GroupMember>) -> Self {
        let map = members
            .into_iter()
            .map(|m| (m.node_id.clone(), m))
            .collect();
        Self {
            group_id: group_id.into(),
            mode,
            membership_epoch: 1,
            next_slot: 1,
            max_lease_ttl_ms: 300_000,
            members: map,
            active_leases: HashMap::new(),
            max_fencing_epoch: HashMap::new(),
            seen_votes: HashMap::new(),
            equivocations: Vec::new(),
            db: None,
        }
    }

    pub async fn open_durable(
        db: Arc<Database>,
        group_id: impl Into<String>,
        mode: ConsensusMode,
        initial_members: Vec<GroupMember>,
    ) -> Result<Self> {
        let gid = group_id.into();
        let ddl = "\
            DEFINE TABLE IF NOT EXISTS sys_mesh_membership SCHEMALESS;\
            DEFINE TABLE IF NOT EXISTS sys_mesh_decision_log SCHEMALESS;";
        let _ = db.client.query(ddl).await;

        let mut group = Self::new(gid.clone(), mode, initial_members);
        group.db = Some(db.clone());

        let gkey = blake3::hash(gid.as_bytes()).to_hex().to_string();
        let mut mresp = db
            .client
            .query("SELECT * FROM type::record('sys_mesh_membership', $id)")
            .bind(("id", gkey))
            .await?;
        let mrows: Vec<serde_json::Value> = mresp.take(0).unwrap_or_default();
        if let Some(rec) = mrows
            .first()
            .and_then(|v| serde_json::from_value::<DurableMembershipRecord>(v.clone()).ok())
        {
            group.mode = rec.mode;
            group.membership_epoch = rec.membership_epoch;
            group.next_slot = rec.next_slot;
            group.members = rec
                .members
                .into_iter()
                .map(|m| (m.node_id.clone(), m))
                .collect();
        } else {
            let mems: Vec<GroupMember> = group.members.values().cloned().collect();
            group.persist_membership_record(group.membership_epoch, group.next_slot, &mems).await?;
        }

        let mut lresp = db.client.query("SELECT * FROM sys_mesh_decision_log").await?;
        let lrows: Vec<serde_json::Value> = lresp.take(0).unwrap_or_default();
        for v in lrows {
            if let Ok(lease) = serde_json::from_value::<FencedLease>(v) {
                if lease.group_id == gid {
                    let cur_max = group.max_fencing_epoch.get(&lease.resource_key).copied().unwrap_or(0);
                    if lease.fencing_epoch > cur_max {
                        group.max_fencing_epoch.insert(lease.resource_key.clone(), lease.fencing_epoch);
                        group.active_leases.insert(lease.resource_key.clone(), lease.clone());
                    }
                    if lease.qc.slot >= group.next_slot {
                        group.next_slot = lease.qc.slot + 1;
                    }
                }
            }
        }
        Ok(group)
    }

    async fn persist_membership_record(
        &self,
        membership_epoch: u64,
        next_slot: u64,
        members: &[GroupMember],
    ) -> Result<()> {
        let Some(ref db) = self.db else { return Ok(()) };
        let gkey = blake3::hash(self.group_id.as_bytes()).to_hex().to_string();
        let rec = DurableMembershipRecord {
            group_id: self.group_id.clone(),
            mode: self.mode,
            membership_epoch,
            next_slot,
            members: members.to_vec(),
        };
        let val = serde_json::to_value(&rec)?;
        db.client
            .query("UPSERT type::record('sys_mesh_membership', $id) CONTENT $m;")
            .bind(("id", gkey))
            .bind(("m", val))
            .await?
            .check()?;
        Ok(())
    }

    /// Unified atomic slot-commit arbitration shared by BOTH `commit_exclusive_lease` AND
    /// `recover_and_commit_slot`!
    ///
    /// Persists the slot decision (`CREATE` insert-if-absent keyed by `(group, epoch, slot)`) AND
    /// membership `next_slot` advancement inside ONE `nexus-db` transaction. If a decision already
    /// exists for `(group, epoch, slot)`, verifies exact digest match (idempotent) or FAILS CLOSED
    /// on conflict!
    async fn persist_slot_decision_atomic(&self, lease: &FencedLease, new_next_slot: u64) -> Result<()> {
        let Some(ref db) = self.db else { return Ok(()) };
        let skey = slot_decision_key(&lease.group_id, lease.qc.epoch, lease.qc.slot);
        let gkey = blake3::hash(self.group_id.as_bytes()).to_hex().to_string();
        let lease_val = serde_json::to_value(lease)?;
        let mem_rec = DurableMembershipRecord {
            group_id: self.group_id.clone(),
            mode: self.mode,
            membership_epoch: self.membership_epoch,
            next_slot: new_next_slot,
            members: self.members.values().cloned().collect(),
        };
        let mem_val = serde_json::to_value(&mem_rec)?;

        let tx_res = db
            .client
            .query(
                "BEGIN TRANSACTION;\
                 CREATE type::record('sys_mesh_decision_log', $skey) CONTENT $l;\
                 UPSERT type::record('sys_mesh_membership', $gkey) CONTENT $m;\
                 COMMIT TRANSACTION;",
            )
            .bind(("skey", skey.clone()))
            .bind(("l", lease_val))
            .bind(("gkey", gkey))
            .bind(("m", mem_val))
            .await;

        match tx_res {
            Ok(resp) => match resp.check() {
                Ok(_) => return Ok(()),
                Err(e) if is_already_exists_error(&e) => {}
                Err(e) => return Err(anyhow!("Failed atomic slot commit transaction: {}", e)),
            },
            Err(e) if is_already_exists_error(&e) => {}
            Err(e) => return Err(anyhow!("Database error in atomic slot commit: {}", e)),
        }

        // Slot record already exists in `sys_mesh_decision_log`: verify exact digest match or fail closed!
        let mut resp = db
            .client
            .query("SELECT * FROM type::record('sys_mesh_decision_log', $skey)")
            .bind(("skey", skey))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let existing: FencedLease = rows
            .first()
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .ok_or_else(|| anyhow!("Slot decision reported existing but could not be read back"))?;
        if existing.canonical_digest() != lease.canonical_digest() {
            anyhow::bail!(
                "CRITICAL: Conflicting durable decision already committed for ({}, epoch={}, slot={})",
                lease.group_id,
                lease.qc.epoch,
                lease.qc.slot
            );
        }
        Ok(())
    }

    /// Read ALL durable decisions in `sys_mesh_decision_log` matching `(self.group_id, self.membership_epoch, slot)`.
    async fn read_durable_slot_decisions(&self, slot: u64) -> Result<Vec<FencedLease>> {
        let Some(ref db) = self.db else {
            return Ok(self
                .active_leases
                .values()
                .filter(|l| l.qc.slot == slot && l.qc.epoch == self.membership_epoch)
                .cloned()
                .collect());
        };
        let mut resp = db.client.query("SELECT * FROM sys_mesh_decision_log").await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        Ok(rows
            .into_iter()
            .filter_map(|v| serde_json::from_value::<FencedLease>(v).ok())
            .filter(|l| l.group_id == self.group_id && l.qc.epoch == self.membership_epoch && l.qc.slot == slot)
            .collect())
    }

    pub fn quorum_size(&self) -> usize {
        self.mode.quorum_size(self.members.len())
    }

    /// Autonomous standby coordinator recovery & commit for `slot`:
    /// 1. Reads durable `sys_mesh_decision_log` and rejects conflicting committed decisions.
    /// 2. Validates every `(SignedVote, Option<LeaseProposal>)` from voters' durable locks.
    /// 3. Reconstructs the unique verified `QuorumCertificate` (failing closed on conflicting quorums).
    /// 4. Requires a matching canonical `LeaseProposal` (fails closed on legacy locks missing payload).
    /// 5. Commits the reconstructed `FencedLease` via the SAME `persist_slot_decision_atomic` path
    ///    and updates in-memory state ONLY after durable persistence succeeds!
    pub async fn recover_and_commit_slot(
        &mut self,
        slot: u64,
        locked_entries: Vec<(SignedVote, Option<LeaseProposal>)>,
    ) -> Result<Option<FencedLease>> {
        // 1. Reconcile complete durable decision log for this slot
        let durable_decisions = self.read_durable_slot_decisions(slot).await?;
        let mut distinct_durable_digests = HashSet::new();
        for d in &durable_decisions {
            distinct_durable_digests.insert(d.canonical_digest());
        }
        if distinct_durable_digests.len() > 1 {
            anyhow::bail!(
                "CRITICAL: Conflicting durable decisions exist in sys_mesh_decision_log for slot {}!",
                slot
            );
        }
        let existing_durable = durable_decisions.into_iter().next();

        // 2. Validate voter locks & proposal payloads
        let mut votes_by_hash: HashMap<String, Vec<SignedVote>> = HashMap::new();
        let mut proposals_by_hash: HashMap<String, LeaseProposal> = HashMap::new();
        for (v, prop_opt) in locked_entries {
            if v.group_id != self.group_id || v.epoch != self.membership_epoch || v.slot != slot {
                continue;
            }
            if let Some(ref p) = prop_opt {
                if p.canonical_digest() != v.proposal_hash {
                    anyhow::bail!(
                        "Malformed or tampered LeaseProposal from voter '{}' for slot {}: digest mismatch",
                        v.voter_node_id,
                        slot
                    );
                }
                if let Some(prev_p) = proposals_by_hash.get(&v.proposal_hash) {
                    if prev_p != p {
                        anyhow::bail!("Conflicting proposal payloads for hash '{}' in slot {}", v.proposal_hash, slot);
                    }
                } else {
                    proposals_by_hash.insert(v.proposal_hash.clone(), p.clone());
                }
            }
            votes_by_hash.entry(v.proposal_hash.clone()).or_default().push(v);
        }

        // 3. Establish unique valid QC
        let mut valid_qcs = Vec::new();
        for (proposal_hash, votes) in votes_by_hash {
            let qc = QuorumCertificate {
                group_id: self.group_id.clone(),
                epoch: self.membership_epoch,
                slot,
                proposal_hash,
                mode: self.mode,
                votes,
            };
            if self.verify_qc(&qc).is_ok() {
                valid_qcs.push(qc);
            }
        }
        if valid_qcs.len() > 1 {
            anyhow::bail!("CRITICAL: Conflicting quorum certificates detected during slot {} recovery!", slot);
        }

        if let Some(committed) = existing_durable {
            if let Some(ref recovered_qc) = valid_qcs.first() {
                if recovered_qc.proposal_hash != committed.canonical_digest() {
                    anyhow::bail!(
                        "CRITICAL: Recovered voter quorum conflicts with durable committed decision for slot {}!",
                        slot
                    );
                }
            }
            // Hydrate in-memory state from durable decision
            if slot >= self.next_slot {
                self.next_slot = slot + 1;
            }
            let cur_max = self.max_fencing_epoch.get(&committed.resource_key).copied().unwrap_or(0);
            if committed.fencing_epoch > cur_max {
                self.max_fencing_epoch.insert(committed.resource_key.clone(), committed.fencing_epoch);
                self.active_leases.insert(committed.resource_key.clone(), committed.clone());
            }
            return Ok(Some(committed));
        }

        let Some(qc) = valid_qcs.into_iter().next() else {
            return Ok(None);
        };

        // 4. Require canonical LeaseProposal (fail closed for legacy locks missing proposal payload!)
        let proposal = proposals_by_hash.remove(&qc.proposal_hash).ok_or_else(|| {
            anyhow!(
                "Cannot autonomously recover slot {}: durable voter locks lack canonical LeaseProposal payload",
                slot
            )
        })?;
        if proposal.group_id != self.group_id {
            anyhow::bail!("Recovered proposal group_id '{}' mismatch", proposal.group_id);
        }
        if proposal.expires_at_ms <= proposal.issued_at_ms
            || proposal.expires_at_ms - proposal.issued_at_ms > self.max_lease_ttl_ms
        {
            anyhow::bail!("Recovered proposal violates group lease validity/TTL bounds");
        }

        let lease = FencedLease {
            lease_id: proposal.lease_id,
            group_id: proposal.group_id,
            resource_key: proposal.resource_key,
            holder_node_id: proposal.holder_node_id,
            workload_id: proposal.workload_id,
            fencing_epoch: proposal.fencing_epoch,
            issued_at_ms: proposal.issued_at_ms,
            expires_at_ms: proposal.expires_at_ms,
            qc,
        };

        // 5. Persist atomically BEFORE publishing into in-memory state!
        let new_next_slot = self.next_slot.max(slot + 1);
        self.persist_slot_decision_atomic(&lease, new_next_slot).await?;

        self.next_slot = new_next_slot;
        let cur_max = self.max_fencing_epoch.get(&lease.resource_key).copied().unwrap_or(0);
        if lease.fencing_epoch > cur_max {
            self.max_fencing_epoch.insert(lease.resource_key.clone(), lease.fencing_epoch);
            self.active_leases.insert(lease.resource_key.clone(), lease.clone());
        }
        Ok(Some(lease))
    }

    pub async fn reconfigure_membership_with_quorum(
        &mut self,
        new_members: Vec<GroupMember>,
        votes: Vec<SignedVote>,
    ) -> Result<u64> {
        let next_epoch = self.membership_epoch + 1;
        let expected_hash = hash_membership_change(&self.group_id, next_epoch, self.mode, &new_members)?;
        let slot = self.next_slot;

        let mut valid_votes = Vec::new();
        let mut unique = HashSet::new();
        for v in votes {
            if v.slot == slot && v.proposal_hash == expected_hash {
                if let Some(eq) = self.record_and_verify_vote(&v)? {
                    anyhow::bail!("Equivocation during membership change from '{}'", eq.voter_node_id);
                }
                if unique.insert(v.voter_node_id.clone()) {
                    valid_votes.push(v);
                }
            }
        }
        let qc = QuorumCertificate {
            group_id: self.group_id.clone(),
            epoch: self.membership_epoch,
            slot,
            proposal_hash: expected_hash,
            mode: self.mode,
            votes: valid_votes,
        };
        self.verify_qc(&qc)?;

        let new_next_slot = self.next_slot + 1;
        self.persist_membership_record(next_epoch, new_next_slot, &new_members)
            .await?;

        self.membership_epoch = next_epoch;
        self.next_slot = new_next_slot;
        self.members = new_members
            .into_iter()
            .map(|m| (m.node_id.clone(), m))
            .collect();
        Ok(self.membership_epoch)
    }

    pub fn record_and_verify_vote(&mut self, vote: &SignedVote) -> Result<Option<EquivocationProof>> {
        if vote.group_id != self.group_id || vote.epoch != self.membership_epoch {
            anyhow::bail!(
                "Vote group/epoch mismatch: expected ({}, {}), got ({}, {})",
                self.group_id,
                self.membership_epoch,
                vote.group_id,
                vote.epoch
            );
        }
        let member = self
            .members
            .get(&vote.voter_node_id)
            .ok_or_else(|| anyhow!("Unknown voter node '{}'", vote.voter_node_id))?;
        let payload = canonical_vote_payload(
            &vote.group_id,
            vote.epoch,
            vote.slot,
            &vote.proposal_hash,
            &vote.voter_node_id,
        );
        if !nexus_db::auth::ed25519_verify(&member.ed25519_pubkey, &payload, &vote.signature) {
            anyhow::bail!("Invalid Ed25519 vote signature from node '{}'", vote.voter_node_id);
        }

        let key = (vote.epoch, vote.slot, vote.voter_node_id.clone());
        if let Some(prev) = self.seen_votes.get(&key) {
            if prev.proposal_hash != vote.proposal_hash {
                let proof = EquivocationProof {
                    group_id: self.group_id.clone(),
                    epoch: vote.epoch,
                    slot: vote.slot,
                    voter_node_id: vote.voter_node_id.clone(),
                    vote_a: prev.clone(),
                    vote_b: vote.clone(),
                };
                self.equivocations.push(proof.clone());
                return Ok(Some(proof));
            }
        } else {
            self.seen_votes.insert(key, vote.clone());
        }
        Ok(None)
    }

    pub fn verify_qc(&self, qc: &QuorumCertificate) -> Result<()> {
        if qc.group_id != self.group_id || qc.mode != self.mode || qc.epoch != self.membership_epoch {
            anyhow::bail!(
                "QC mismatch: expected (group={}, epoch={}, mode={:?}), got (group={}, epoch={}, mode={:?})",
                self.group_id,
                self.membership_epoch,
                self.mode,
                qc.group_id,
                qc.epoch,
                qc.mode
            );
        }
        let mut unique_voters = HashSet::new();
        for v in &qc.votes {
            if v.group_id != qc.group_id || v.epoch != qc.epoch || v.slot != qc.slot || v.proposal_hash != qc.proposal_hash {
                anyhow::bail!("QC contains mismatched vote");
            }
            let member = self
                .members
                .get(&v.voter_node_id)
                .ok_or_else(|| anyhow!("QC voter '{}' not in group", v.voter_node_id))?;
            let payload = canonical_vote_payload(&v.group_id, v.epoch, v.slot, &v.proposal_hash, &v.voter_node_id);
            if !nexus_db::auth::ed25519_verify(&member.ed25519_pubkey, &payload, &v.signature) {
                anyhow::bail!("QC contains invalid signature from '{}'", v.voter_node_id);
            }
            unique_voters.insert(v.voter_node_id.clone());
        }
        let required = self.quorum_size();
        if unique_voters.len() < required {
            anyhow::bail!(
                "Insufficient quorum for {:?}: got {} valid votes, need {}",
                self.mode,
                unique_voters.len(),
                required
            );
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn commit_exclusive_lease(
        &mut self,
        lease_id: &str,
        resource_key: &str,
        holder_node_id: &str,
        workload_id: &str,
        issued_at_ms: u64,
        expires_at_ms: u64,
        now: u64,
        votes: Vec<SignedVote>,
    ) -> Result<FencedLease> {
        if !self.members.contains_key(holder_node_id) {
            anyhow::bail!("Holder '{}' is not an authorized member of group '{}'", holder_node_id, self.group_id);
        }
        if expires_at_ms <= issued_at_ms {
            anyhow::bail!("Invalid lease interval: expires_at_ms <= issued_at_ms");
        }
        if expires_at_ms - issued_at_ms > self.max_lease_ttl_ms {
            anyhow::bail!("Requested lease duration exceeds group max_lease_ttl_ms");
        }
        if let Some(existing) = self.active_leases.get(resource_key) {
            if existing.expires_at_ms > now && existing.holder_node_id != holder_node_id {
                anyhow::bail!(
                    "Resource '{}' is exclusively leased by '{}' (fencing_epoch={}) until {}",
                    resource_key,
                    existing.holder_node_id,
                    existing.fencing_epoch,
                    existing.expires_at_ms
                );
            }
        }

        let next_fencing = self.max_fencing_epoch.get(resource_key).copied().unwrap_or(0) + 1;
        let slot = self.next_slot;
        let expected_hash = hash_lease_proposal(
            &self.group_id,
            lease_id,
            resource_key,
            holder_node_id,
            workload_id,
            next_fencing,
            issued_at_ms,
            expires_at_ms,
        );

        let mut valid_votes = Vec::new();
        let mut unique_voters = HashSet::new();
        for v in votes {
            if v.slot != slot || v.proposal_hash != expected_hash {
                continue;
            }
            if let Some(equiv) = self.record_and_verify_vote(&v)? {
                anyhow::bail!(
                    "Equivocation detected from '{}' at slot {}",
                    equiv.voter_node_id,
                    equiv.slot
                );
            }
            if unique_voters.insert(v.voter_node_id.clone()) {
                valid_votes.push(v);
            }
        }

        let required = self.quorum_size();
        if valid_votes.len() < required {
            anyhow::bail!(
                "Quorum not reached for '{}' ({:?}): got {} valid votes, need {}",
                resource_key,
                self.mode,
                valid_votes.len(),
                required
            );
        }

        let qc = QuorumCertificate {
            group_id: self.group_id.clone(),
            epoch: self.membership_epoch,
            slot,
            proposal_hash: expected_hash,
            mode: self.mode,
            votes: valid_votes,
        };
        self.verify_qc(&qc)?;

        let lease = FencedLease {
            lease_id: lease_id.to_string(),
            group_id: self.group_id.clone(),
            resource_key: resource_key.to_string(),
            holder_node_id: holder_node_id.to_string(),
            workload_id: workload_id.to_string(),
            fencing_epoch: next_fencing,
            issued_at_ms,
            expires_at_ms,
            qc,
        };
        let new_next_slot = self.next_slot + 1;
        self.persist_slot_decision_atomic(&lease, new_next_slot).await?;
        self.next_slot = new_next_slot;
        self.max_fencing_epoch.insert(resource_key.to_string(), next_fencing);
        self.active_leases.insert(resource_key.to_string(), lease.clone());
        Ok(lease)
    }

    pub fn expire_lease_for_fault(&mut self, resource_key: &str, now: u64) {
        if let Some(l) = self.active_leases.get_mut(resource_key) {
            l.expires_at_ms = now.saturating_sub(1);
        }
    }

    pub fn now_ms() -> u64 {
        now_ms()
    }
}
