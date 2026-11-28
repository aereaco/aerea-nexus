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

/// Canonical, versioned membership-transition proposal (`NEXUS-MEMBERSHIP-TRANSITION-v2`).
///
/// Bound into the same durable per-voter `(group_id, epoch, slot)` lock mechanism as `LeaseProposal`
/// with strict proposal-type domain separation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipTransitionProposal {
    pub group_id: String,
    pub prev_epoch: u64,
    pub next_epoch: u64,
    pub slot: u64,
    pub mode: ConsensusMode,
    pub new_members: Vec<GroupMember>,
}

impl MembershipTransitionProposal {
    pub fn new(
        group_id: impl Into<String>,
        prev_epoch: u64,
        next_epoch: u64,
        slot: u64,
        mode: ConsensusMode,
        new_members: Vec<GroupMember>,
    ) -> Result<Self> {
        let mut sorted = new_members;
        sorted.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        let prop = Self {
            group_id: group_id.into(),
            prev_epoch,
            next_epoch,
            slot,
            mode,
            new_members: sorted,
        };
        let _ = prop.canonical_digest()?;
        Ok(prop)
    }

    /// Single canonical length-prefixed encoding (`NEXUS-MEMBERSHIP-TRANSITION-v2`), strictly
    /// domain-separated from `NEXUS-LEASE-PROPOSAL-v2`.
    pub fn canonical_digest(&self) -> Result<String> {
        if self.next_epoch != self.prev_epoch.saturating_add(1) {
            anyhow::bail!(
                "Invalid membership transition epoch jump: prev_epoch={} -> next_epoch={}",
                self.prev_epoch,
                self.next_epoch
            );
        }
        if self.new_members.is_empty() {
            anyhow::bail!("Membership transition cannot have an empty member set");
        }
        let mut sorted = self.new_members.clone();
        sorted.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        let mut seen = HashSet::new();
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"NEXUS-MEMBERSHIP-TRANSITION-v2");
        push_len_prefixed(&mut hasher, self.group_id.as_bytes());
        hasher.update(&self.prev_epoch.to_be_bytes());
        hasher.update(&self.next_epoch.to_be_bytes());
        hasher.update(&self.slot.to_be_bytes());
        push_len_prefixed(&mut hasher, self.mode.canonical_tag().as_bytes());
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
}

/// Canonical protocol-defined NoOp proposal (`NEXUS-NOOP-PROPOSAL-v2`) used during multi-slot
/// takeover catch-up to establish an explicit, verifiable disposition for unaccepted gap slots
/// rather than silently skipping them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoOpProposal {
    pub group_id: String,
    pub epoch: u64,
    pub slot: u64,
    pub reason: String,
}

impl NoOpProposal {
    pub fn canonical_digest(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"NEXUS-NOOP-PROPOSAL-v2");
        push_len_prefixed(&mut hasher, self.group_id.as_bytes());
        hasher.update(&self.epoch.to_be_bytes());
        hasher.update(&self.slot.to_be_bytes());
        push_len_prefixed(&mut hasher, self.reason.as_bytes());
        hasher.finalize().to_hex().to_string()
    }
}

/// Unified canonical slot proposal used across `VoteRequest`, `DurableVoterLock`, QC verification,
/// autonomous recovery, and durable slot persistence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SlotProposal {
    Lease(LeaseProposal),
    Membership(MembershipTransitionProposal),
    NoOp(NoOpProposal),
}

impl SlotProposal {
    pub fn group_id(&self) -> &str {
        match self {
            Self::Lease(p) => &p.group_id,
            Self::Membership(p) => &p.group_id,
            Self::NoOp(p) => &p.group_id,
        }
    }

    pub fn canonical_digest(&self) -> Result<String> {
        match self {
            Self::Lease(p) => Ok(p.canonical_digest()),
            Self::Membership(p) => p.canonical_digest(),
            Self::NoOp(p) => Ok(p.canonical_digest()),
        }
    }

    pub fn validate_for_vote(&self, group_id: &str, epoch: u64, slot: u64) -> Result<String> {
        if self.group_id() != group_id {
            anyhow::bail!(
                "Proposal group_id '{}' does not match vote group_id '{}'",
                self.group_id(),
                group_id
            );
        }
        match self {
            Self::Lease(_) => {}
            Self::Membership(m) => {
                if m.prev_epoch != epoch || m.next_epoch != epoch.saturating_add(1) {
                    anyhow::bail!(
                        "Membership transition epoch ({} -> {}) does not match vote epoch {}",
                        m.prev_epoch,
                        m.next_epoch,
                        epoch
                    );
                }
                if m.slot != slot {
                    anyhow::bail!(
                        "Membership transition slot {} does not match vote slot {}",
                        m.slot,
                        slot
                    );
                }
            }
            Self::NoOp(n) => {
                if n.epoch != epoch || n.slot != slot {
                    anyhow::bail!(
                        "NoOp proposal (epoch={}, slot={}) does not match vote (epoch={}, slot={})",
                        n.epoch,
                        n.slot,
                        epoch,
                        slot
                    );
                }
            }
        }
        self.canonical_digest()
    }
}

/// Phase-1 prepare request sent by a candidate coordinator to establish a durable monotonic term.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrepareTermRequest {
    pub group_id: String,
    pub epoch: u64,
    pub term: u64,
    pub leader_id: String,
    pub from_slot: u64,
}

/// Durable accepted lock reported by a voter inside its signed `TermPromise`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedSlotLock {
    pub epoch: u64,
    pub slot: u64,
    pub accepted_term: u64,
    pub proposal_hash: String,
    pub proposal: SlotProposal,
    pub vote: SignedVote,
}

/// Cryptographically signed voter promise for `(group_id, epoch, term, leader_id)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TermPromise {
    pub group_id: String,
    pub epoch: u64,
    pub term: u64,
    pub leader_id: String,
    pub from_slot: u64,
    pub voter_node_id: String,
    pub min_active_epoch: u64,
    pub accepted_locks: Vec<AcceptedSlotLock>,
    pub signature: String,
}

/// Quorum certificate of signed `TermPromise`s proving a coordinator's authority in `term` AND
/// enabling voters to independently verify Paxos value adoption before signing higher-term votes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TermCertificate {
    pub group_id: String,
    pub epoch: u64,
    pub term: u64,
    pub leader_id: String,
    pub from_slot: u64,
    pub mode: ConsensusMode,
    pub promises: Vec<TermPromise>,
}

/// Recovery action planned for a single slot in the contiguous takeover prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlotRecoveryAction {
    Adopt(SlotProposal),
    FillGapNoOp(NoOpProposal),
}

/// Typed genesis-anchor trust errors returned when a voter lacks an independently provisioned
/// trust anchor or when a supplied genesis configuration contradicts its pinned anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisAnchorError {
    MissingTrustedGenesisAnchor {
        voter_node_id: String,
        group_id: String,
    },
    AnchorMismatch {
        voter_node_id: String,
        group_id: String,
    },
}

impl std::fmt::Display for GenesisAnchorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingTrustedGenesisAnchor {
                voter_node_id,
                group_id,
            } => write!(
                f,
                "Voter '{}' has no independently provisioned trusted genesis anchor for '{}'",
                voter_node_id, group_id
            ),
            Self::AnchorMismatch {
                voter_node_id,
                group_id,
            } => write!(
                f,
                "Supplied genesis configuration disagrees with voter '{}' pinned trusted genesis anchor for '{}'",
                voter_node_id, group_id
            ),
        }
    }
}

impl std::error::Error for GenesisAnchorError {}

/// Verifiable receipt returned by `VoterNode::install_membership_epoch()`, distinguishing
/// old-epoch barrier installation from new-epoch activation and preserving any unresolved
/// post-transition old-epoch accepted locks for recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochInstallReceipt {
    pub voter_node_id: String,
    pub min_active_epoch: u64,
    pub barrier_slot: u64,
    pub post_transition_old_locks: Vec<AcceptedSlotLock>,
}

/// Summary of an autonomous multi-slot coordinator takeover & catch-up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeoverReport {
    pub term: u64,
    pub membership_epoch: u64,
    pub next_slot: u64,
    pub recovered_slots: Vec<u64>,
    pub filled_gaps: Vec<u64>,
    /// Operational telemetry: removed voters that were unreachable during epoch transition
    /// activation (safety is still enforced by the old-configuration fence quorum).
    #[serde(default)]
    pub pending_removed_fence_nodes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteRequest {
    pub group_id: String,
    pub epoch: u64,
    pub slot: u64,
    pub proposal_hash: String,
    /// Canonical slot proposal persisted atomically with the voter's durable lock for recovery.
    #[serde(default)]
    pub proposal: Option<SlotProposal>,
    /// Coordinator term (`>= 1` for term-fenced votes; `0` for legacy Milestone-1 compatibility).
    #[serde(default)]
    pub term: u64,
    #[serde(default)]
    pub leader_id: Option<String>,
    /// Verifiable Phase-1 quorum certificate required for all term-fenced votes (`term >= 1`).
    #[serde(default)]
    pub term_cert: Option<TermCertificate>,
}

impl VoteRequest {
    pub fn for_lease(epoch: u64, slot: u64, proposal: LeaseProposal) -> Self {
        let proposal_hash = proposal.canonical_digest();
        Self {
            group_id: proposal.group_id.clone(),
            epoch,
            slot,
            proposal_hash,
            proposal: Some(SlotProposal::Lease(proposal)),
            term: 0,
            leader_id: None,
            term_cert: None,
        }
    }

    pub fn for_membership(proposal: MembershipTransitionProposal) -> Result<Self> {
        let proposal_hash = proposal.canonical_digest()?;
        Ok(Self {
            group_id: proposal.group_id.clone(),
            epoch: proposal.prev_epoch,
            slot: proposal.slot,
            proposal_hash,
            proposal: Some(SlotProposal::Membership(proposal)),
            term: 0,
            leader_id: None,
            term_cert: None,
        })
    }

    pub fn for_noop(proposal: NoOpProposal) -> Self {
        let proposal_hash = proposal.canonical_digest();
        Self {
            group_id: proposal.group_id.clone(),
            epoch: proposal.epoch,
            slot: proposal.slot,
            proposal_hash,
            proposal: Some(SlotProposal::NoOp(proposal)),
            term: 0,
            leader_id: None,
            term_cert: None,
        }
    }

    pub fn with_term(
        mut self,
        term: u64,
        leader_id: impl Into<String>,
        term_cert: TermCertificate,
    ) -> Self {
        self.term = term;
        self.leader_id = Some(leader_id.into());
        self.term_cert = Some(term_cert);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedVote {
    pub group_id: String,
    pub epoch: u64,
    #[serde(default)]
    pub term: u64,
    pub slot: u64,
    pub proposal_hash: String,
    pub voter_node_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumCertificate {
    pub group_id: String,
    pub epoch: u64,
    #[serde(default)]
    pub term: u64,
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

/// Verifiable durable membership-transition decision binding the canonical proposal and the
/// predecessor-epoch QuorumCertificate that authorized it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipTransitionDecision {
    pub proposal: MembershipTransitionProposal,
    pub qc: QuorumCertificate,
}

impl MembershipTransitionDecision {
    pub fn canonical_digest(&self) -> Result<String> {
        self.proposal.canonical_digest()
    }
}

/// Verifiable durable NoOp decision persisted when filling an unaccepted gap slot during takeover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoOpDecision {
    pub proposal: NoOpProposal,
    pub qc: QuorumCertificate,
}

impl NoOpDecision {
    pub fn canonical_digest(&self) -> String {
        self.proposal.canonical_digest()
    }
}

/// Type-aware durable slot decision persisted in `sys_mesh_decision_log`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "decision_kind", rename_all = "snake_case")]
pub enum DurableSlotDecision {
    Lease(FencedLease),
    Membership(MembershipTransitionDecision),
    NoOp(NoOpDecision),
}

impl DurableSlotDecision {
    pub fn group_id(&self) -> &str {
        match self {
            Self::Lease(l) => &l.group_id,
            Self::Membership(m) => &m.proposal.group_id,
            Self::NoOp(n) => &n.proposal.group_id,
        }
    }

    pub fn qc(&self) -> &QuorumCertificate {
        match self {
            Self::Lease(l) => &l.qc,
            Self::Membership(m) => &m.qc,
            Self::NoOp(n) => &n.qc,
        }
    }

    pub fn canonical_digest(&self) -> Result<String> {
        match self {
            Self::Lease(l) => Ok(l.canonical_digest()),
            Self::Membership(m) => m.canonical_digest(),
            Self::NoOp(n) => Ok(n.canonical_digest()),
        }
    }

    pub fn as_lease(&self) -> Option<&FencedLease> {
        match self {
            Self::Lease(l) => Some(l),
            Self::Membership(_) | Self::NoOp(_) => None,
        }
    }

    pub fn as_membership(&self) -> Option<&MembershipTransitionDecision> {
        match self {
            Self::Membership(m) => Some(m),
            Self::Lease(_) | Self::NoOp(_) => None,
        }
    }

    pub fn as_noop(&self) -> Option<&NoOpDecision> {
        match self {
            Self::NoOp(n) => Some(n),
            Self::Lease(_) | Self::Membership(_) => None,
        }
    }
}

fn decision_row_group_id(v: &serde_json::Value) -> Option<&str> {
    v.get("group_id")
        .and_then(|g| g.as_str())
        .or_else(|| v.get("proposal").and_then(|p| p.get("group_id")).and_then(|g| g.as_str()))
}

/// Parse a durable `sys_mesh_decision_log` row while preserving backward compatibility with
/// previously persisted untagged `FencedLease` records and failing closed on malformed JSON.
fn parse_durable_slot_decision(v: serde_json::Value) -> Result<DurableSlotDecision> {
    if v.get("decision_kind").is_some() {
        return serde_json::from_value::<DurableSlotDecision>(v)
            .map_err(|e| anyhow!("Malformed tagged DurableSlotDecision record: {}", e));
    }
    if v.get("lease_id").is_some() {
        let lease: FencedLease = serde_json::from_value(v)
            .map_err(|e| anyhow!("Malformed legacy FencedLease decision record: {}", e))?;
        return Ok(DurableSlotDecision::Lease(lease));
    }
    anyhow::bail!("Malformed durable decision record: missing decision_kind / lease_id")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DurableVoterLock {
    lock_key: String,
    group_id: String,
    epoch: u64,
    #[serde(default)]
    accepted_term: u64,
    slot: u64,
    proposal_hash: String,
    #[serde(default)]
    proposal: Option<SlotProposal>,
    voter_node_id: String,
    signature: String,
    locked_at_ms: u64,
}

/// Durable per-voter term promise & authorized membership epoch high-water mark.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DurableVoterTermState {
    term_key: String,
    group_id: String,
    voter_node_id: String,
    promised_term: u64,
    promised_leader_id: Option<String>,
    min_active_epoch: u64,
    #[serde(default)]
    trusted_genesis_digest: Option<String>,
    /// Durable per-epoch log barrier: once a membership transition at `(epoch, slot)` is accepted
    /// or installed, this voter refuses all further votes in `epoch` for `slot > barrier_slot`.
    #[serde(default)]
    epoch_barriers: HashMap<u64, u64>,
    #[serde(default)]
    installed_epochs: HashMap<u64, MembershipEpochConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipEpochConfig {
    pub mode: ConsensusMode,
    pub members: HashMap<String, GroupMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DurableMembershipRecord {
    group_id: String,
    mode: ConsensusMode,
    membership_epoch: u64,
    #[serde(default)]
    current_term: u64,
    next_slot: u64,
    members: Vec<GroupMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DurableMembershipEpochRecord {
    group_id: String,
    membership_epoch: u64,
    mode: ConsensusMode,
    members: Vec<GroupMember>,
    /// `None` only for genesis epoch 1; mandatory verified transition certificate for every epoch > 1.
    #[serde(default)]
    transition: Option<MembershipTransitionDecision>,
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
    canonical_vote_payload_for_term(group_id, epoch, 0, slot, proposal_hash, voter_node_id)
}

pub fn canonical_vote_payload_for_term(
    group_id: &str,
    epoch: u64,
    term: u64,
    slot: u64,
    proposal_hash: &str,
    voter_node_id: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(140);
    if term == 0 {
        out.extend_from_slice(b"NEXUS-CONSENSUS-VOTE-v1");
    } else {
        out.extend_from_slice(b"NEXUS-CONSENSUS-VOTE-v2");
    }
    for field in [group_id.as_bytes(), proposal_hash.as_bytes(), voter_node_id.as_bytes()] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field);
    }
    out.extend_from_slice(&epoch.to_be_bytes());
    if term > 0 {
        out.extend_from_slice(&term.to_be_bytes());
    }
    out.extend_from_slice(&slot.to_be_bytes());
    out
}

pub fn canonical_promise_payload(
    group_id: &str,
    epoch: u64,
    term: u64,
    leader_id: &str,
    from_slot: u64,
    voter_node_id: &str,
    min_active_epoch: u64,
    accepted_locks: &[AcceptedSlotLock],
) -> Vec<u8> {
    let mut sorted = accepted_locks.to_vec();
    sorted.sort_by_key(|l| (l.slot, l.accepted_term, l.epoch));
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(b"NEXUS-TERM-PROMISE-v1");
    for field in [group_id.as_bytes(), leader_id.as_bytes(), voter_node_id.as_bytes()] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field);
    }
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&term.to_be_bytes());
    out.extend_from_slice(&from_slot.to_be_bytes());
    out.extend_from_slice(&min_active_epoch.to_be_bytes());
    out.extend_from_slice(&(sorted.len() as u32).to_be_bytes());
    for l in &sorted {
        out.extend_from_slice(&l.epoch.to_be_bytes());
        out.extend_from_slice(&l.slot.to_be_bytes());
        out.extend_from_slice(&l.accepted_term.to_be_bytes());
        let ph = l.proposal_hash.as_bytes();
        out.extend_from_slice(&(ph.len() as u32).to_be_bytes());
        out.extend_from_slice(ph);
    }
    out
}

/// Canonical length-prefixed digest (`NEXUS-GENESIS-ANCHOR-v1`) anchoring a group's trusted
/// epoch-1 genesis membership configuration so newly admitted voters cannot be fooled by a
/// substituted genesis chain.
pub fn hash_genesis_config(
    group_id: &str,
    mode: ConsensusMode,
    members: &[GroupMember],
) -> Result<String> {
    if members.is_empty() {
        anyhow::bail!("Genesis configuration cannot have an empty member set");
    }
    let mut sorted = members.to_vec();
    sorted.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    let mut seen = HashSet::new();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"NEXUS-GENESIS-ANCHOR-v1");
    push_len_prefixed(&mut hasher, group_id.as_bytes());
    push_len_prefixed(&mut hasher, mode.canonical_tag().as_bytes());
    hasher.update(&(sorted.len() as u32).to_be_bytes());
    for m in &sorted {
        if !seen.insert(m.node_id.as_str()) {
            anyhow::bail!("Duplicate node_id '{}' in genesis config", m.node_id);
        }
        push_len_prefixed(&mut hasher, m.node_id.as_bytes());
        push_len_prefixed(&mut hasher, m.identity_id.as_bytes());
        push_len_prefixed(&mut hasher, m.org_id.as_bytes());
        push_len_prefixed(&mut hasher, m.ed25519_pubkey.as_bytes());
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// Pure, shared Phase-1 `TermCertificate` & Paxos value-adoption verifier used by BOTH voters
/// (`VoterNode::cast_vote`) and coordinators (`CoordinationGroup::plan_takeover_from_promises`).
///
/// Protocol invariant:
/// - Verifies a quorum of authorized `epoch_cfg.members` signed `NEXUS-TERM-PROMISE-v1` for
///   `(cert.group_id, cert.epoch, cert.term, cert.leader_id, cert.from_slot)`.
/// - Validates EVERY reported `AcceptedSlotLock` on every promise (epoch, slot >= from_slot,
///   accepted_term < cert.term, no duplicate slots per voter, embedded `SignedVote` fields &
///   Ed25519 signature, and canonical proposal digest). Any malformed lock fails the ENTIRE promise.
/// - For `slot`: selects the unique proposal with the highest `accepted_term` across all promises.
/// - Fails closed if two conflicting proposals share the highest `accepted_term`.
pub fn verify_term_certificate_and_adoption(
    cert: &TermCertificate,
    epoch_cfg: &MembershipEpochConfig,
    slot: u64,
) -> Result<Option<SlotProposal>> {
    if cert.term == 0 || cert.leader_id.is_empty() {
        anyhow::bail!("TermCertificate requires term >= 1 and non-empty leader_id");
    }
    if cert.mode != epoch_cfg.mode {
        anyhow::bail!(
            "TermCertificate mode {:?} does not match epoch config mode {:?}",
            cert.mode,
            epoch_cfg.mode
        );
    }
    if slot < cert.from_slot {
        anyhow::bail!(
            "Slot {} is below TermCertificate from_slot {}",
            slot,
            cert.from_slot
        );
    }

    let mut unique_voters = HashSet::new();
    let mut best_term: Option<u64> = None;
    let mut best_proposal: Option<(String, SlotProposal)> = None;

    for p in &cert.promises {
        if p.group_id != cert.group_id
            || p.epoch != cert.epoch
            || p.term != cert.term
            || p.leader_id != cert.leader_id
            || p.from_slot != cert.from_slot
        {
            anyhow::bail!(
                "TermPromise from '{}' does not match TermCertificate header",
                p.voter_node_id
            );
        }
        let member = epoch_cfg.members.get(&p.voter_node_id).ok_or_else(|| {
            anyhow!(
                "TermPromise voter '{}' is not an authorized member for epoch {}",
                p.voter_node_id,
                cert.epoch
            )
        })?;
        let payload = canonical_promise_payload(
            &p.group_id,
            p.epoch,
            p.term,
            &p.leader_id,
            p.from_slot,
            &p.voter_node_id,
            p.min_active_epoch,
            &p.accepted_locks,
        );
        if !nexus_db::auth::ed25519_verify(&member.ed25519_pubkey, &payload, &p.signature) {
            anyhow::bail!("Invalid Ed25519 signature on TermPromise from '{}'", p.voter_node_id);
        }
        unique_voters.insert(p.voter_node_id.clone());

        let mut seen_slots_for_voter = HashSet::new();
        for lock in &p.accepted_locks {
            if lock.epoch != cert.epoch {
                anyhow::bail!(
                    "Invalid AcceptedSlotLock from '{}': lock epoch {} does not match certificate epoch {}",
                    p.voter_node_id,
                    lock.epoch,
                    cert.epoch
                );
            }
            if lock.slot < cert.from_slot {
                anyhow::bail!(
                    "Invalid AcceptedSlotLock from '{}': slot {} is below from_slot {}",
                    p.voter_node_id,
                    lock.slot,
                    cert.from_slot
                );
            }
            if lock.accepted_term >= cert.term {
                anyhow::bail!(
                    "Invalid AcceptedSlotLock from '{}': accepted_term {} >= certificate term {}",
                    p.voter_node_id,
                    lock.accepted_term,
                    cert.term
                );
            }
            if !seen_slots_for_voter.insert(lock.slot) {
                anyhow::bail!(
                    "Duplicate AcceptedSlotLock for slot {} in TermPromise from '{}'",
                    lock.slot,
                    p.voter_node_id
                );
            }
            // Verify embedded SignedVote agrees with lock & voter identity AND verify its signature!
            let v = &lock.vote;
            if v.group_id != cert.group_id
                || v.epoch != lock.epoch
                || v.term != lock.accepted_term
                || v.slot != lock.slot
                || v.proposal_hash != lock.proposal_hash
                || v.voter_node_id != p.voter_node_id
            {
                anyhow::bail!(
                    "Mismatched embedded SignedVote in AcceptedSlotLock from '{}' at slot {}",
                    p.voter_node_id,
                    lock.slot
                );
            }
            let vote_payload = canonical_vote_payload_for_term(
                &v.group_id,
                v.epoch,
                v.term,
                v.slot,
                &v.proposal_hash,
                &v.voter_node_id,
            );
            if !nexus_db::auth::ed25519_verify(&member.ed25519_pubkey, &vote_payload, &v.signature) {
                anyhow::bail!(
                    "Invalid Ed25519 signature on embedded SignedVote from '{}' at slot {}",
                    p.voter_node_id,
                    lock.slot
                );
            }
            let computed = lock.proposal.validate_for_vote(&cert.group_id, lock.epoch, lock.slot)?;
            if computed != lock.proposal_hash {
                anyhow::bail!(
                    "Tampered AcceptedSlotLock in TermPromise from '{}' at slot {}",
                    p.voter_node_id,
                    lock.slot
                );
            }

            if lock.slot != slot {
                continue;
            }
            match best_term {
                None => {
                    best_term = Some(lock.accepted_term);
                    best_proposal = Some((lock.proposal_hash.clone(), lock.proposal.clone()));
                }
                Some(bt) if lock.accepted_term > bt => {
                    best_term = Some(lock.accepted_term);
                    best_proposal = Some((lock.proposal_hash.clone(), lock.proposal.clone()));
                }
                Some(bt) if lock.accepted_term == bt => {
                    if let Some((ref bh, ref bp)) = best_proposal {
                        if bh != &lock.proposal_hash || bp != &lock.proposal {
                            anyhow::bail!(
                                "CRITICAL: Conflicting accepted proposals share equal highest accepted_term {} at slot {} — takeover fails closed!",
                                bt,
                                slot
                            );
                        }
                    }
                }
                Some(_) => {}
            }
        }
    }

    let required = epoch_cfg.mode.quorum_size(epoch_cfg.members.len());
    if unique_voters.len() < required {
        anyhow::bail!(
            "Insufficient TermCertificate quorum for {:?}: got {} valid promises, need {}",
            epoch_cfg.mode,
            unique_voters.len(),
            required
        );
    }

    Ok(best_proposal.map(|(_, prop)| prop))
}

pub fn sign_vote_raw(
    group_id: &str,
    epoch: u64,
    slot: u64,
    proposal_hash: &str,
    voter_node_id: &str,
    voter_sk_b64: &str,
) -> Result<SignedVote> {
    sign_vote_raw_in_term(group_id, epoch, 0, slot, proposal_hash, voter_node_id, voter_sk_b64)
}

pub fn sign_vote_raw_in_term(
    group_id: &str,
    epoch: u64,
    term: u64,
    slot: u64,
    proposal_hash: &str,
    voter_node_id: &str,
    voter_sk_b64: &str,
) -> Result<SignedVote> {
    let payload =
        canonical_vote_payload_for_term(group_id, epoch, term, slot, proposal_hash, voter_node_id);
    let sig = nexus_db::auth::ed25519_sign(voter_sk_b64, &payload)?;
    Ok(SignedVote {
        group_id: group_id.to_string(),
        epoch,
        term,
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

fn membership_epoch_key(group_id: &str, membership_epoch: u64) -> String {
    format!(
        "{}_e{}",
        &blake3::hash(group_id.as_bytes()).to_hex().as_str()[..16],
        membership_epoch
    )
}

/// Independent durable voter node backed by its own `nexus-db` instance.
#[derive(Clone)]
pub struct VoterNode {
    pub node_id: String,
    pub ed25519_sk_b64: String,
    db: Arc<Database>,
    /// Production voters default to `false` (strictly requiring installed membership config and
    /// `term >= 1` + verifiable `TermCertificate`). Legacy Milestone-1 `term == 0` compatibility
    /// must be explicitly opted into via `with_legacy_term_zero_compat()`.
    allow_legacy_term_zero: bool,
}

impl VoterNode {
    pub fn new(node_id: impl Into<String>, ed25519_sk_b64: impl Into<String>, db: Arc<Database>) -> Self {
        Self {
            node_id: node_id.into(),
            ed25519_sk_b64: ed25519_sk_b64.into(),
            db,
            allow_legacy_term_zero: false,
        }
    }

    /// Explicit opt-in for legacy Milestone-1 `term == 0` compatibility tests only.
    pub fn with_legacy_term_zero_compat(mut self) -> Self {
        self.allow_legacy_term_zero = true;
        self
    }

    pub async fn ensure_tables(&self) -> Result<()> {
        let _ = self
            .db
            .client
            .query(
                "DEFINE TABLE IF NOT EXISTS sys_mesh_voter_lock SCHEMALESS;\
                 DEFINE TABLE IF NOT EXISTS sys_mesh_voter_term SCHEMALESS;",
            )
            .await;
        Ok(())
    }

    fn term_state_key(&self, group_id: &str) -> String {
        format!(
            "{}_{}",
            &blake3::hash(group_id.as_bytes()).to_hex().as_str()[..16],
            self.node_id
        )
    }

    async fn load_term_state(&self, group_id: &str) -> Result<Option<DurableVoterTermState>> {
        self.ensure_tables().await?;
        let tkey = self.term_state_key(group_id);
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_mesh_voter_term', $id)")
            .bind(("id", tkey.clone()))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let Some(raw) = rows.first() else {
            return Ok(None);
        };
        let state: DurableVoterTermState = serde_json::from_value(raw.clone()).map_err(|e| {
            anyhow!(
                "Corrupt durable voter term state on '{}' for '{}': {}",
                self.node_id,
                group_id,
                e
            )
        })?;
        if state.term_key != tkey || state.group_id != group_id || state.voter_node_id != self.node_id {
            anyhow::bail!(
                "Misbound durable voter term state on '{}' for '{}'",
                self.node_id,
                group_id
            );
        }
        Ok(Some(state))
    }

    async fn persist_term_state(&self, state: &DurableVoterTermState) -> Result<()> {
        self.ensure_tables().await?;
        let val = serde_json::to_value(state)?;
        self.db
            .client
            .query("UPSERT type::record('sys_mesh_voter_term', $id) CONTENT $s;")
            .bind(("id", state.term_key.clone()))
            .bind(("s", val))
            .await?
            .check()?;
        Ok(())
    }

    /// Pin a trusted genesis anchor digest (`hash_genesis_config(...)`) on this voter BEFORE
    /// bootstrapping from a membership-transition chain.
    pub async fn set_trusted_genesis_anchor(
        &self,
        group_id: &str,
        genesis_digest: impl Into<String>,
    ) -> Result<()> {
        let _tx = self.db.lock_tx().await;
        let digest = genesis_digest.into();
        let mut state = match self.load_term_state(group_id).await? {
            Some(s) => s,
            None => DurableVoterTermState {
                term_key: self.term_state_key(group_id),
                group_id: group_id.to_string(),
                voter_node_id: self.node_id.clone(),
                promised_term: 0,
                promised_leader_id: None,
                min_active_epoch: 1,
                trusted_genesis_digest: None,
                epoch_barriers: HashMap::new(),
                installed_epochs: HashMap::new(),
            },
        };
        if let Some(ref existing) = state.trusted_genesis_digest {
            if existing != &digest {
                return Err(GenesisAnchorError::AnchorMismatch {
                    voter_node_id: self.node_id.clone(),
                    group_id: group_id.to_string(),
                }
                .into());
            }
            return Ok(());
        }
        state.trusted_genesis_digest = Some(digest);
        self.persist_term_state(&state).await
    }

    /// Explicitly provision and install the genesis epoch-1 membership configuration on this voter
    /// so it can independently verify Phase-1 `TermCertificate`s and enforce epoch fencing.
    pub async fn install_genesis_epoch(
        &self,
        group_id: &str,
        mode: ConsensusMode,
        members: Vec<GroupMember>,
    ) -> Result<String> {
        let _tx = self.db.lock_tx().await;
        let genesis_digest = hash_genesis_config(group_id, mode, &members)?;
        let mut map = HashMap::new();
        for m in members {
            map.insert(m.node_id.clone(), m);
        }
        let cfg = MembershipEpochConfig { mode, members: map };
        let mut state = match self.load_term_state(group_id).await? {
            Some(s) => s,
            None => DurableVoterTermState {
                term_key: self.term_state_key(group_id),
                group_id: group_id.to_string(),
                voter_node_id: self.node_id.clone(),
                promised_term: 0,
                promised_leader_id: None,
                min_active_epoch: 1,
                trusted_genesis_digest: Some(genesis_digest.clone()),
                epoch_barriers: HashMap::new(),
                installed_epochs: HashMap::new(),
            },
        };
        if let Some(ref pinned) = state.trusted_genesis_digest {
            if pinned != &genesis_digest {
                return Err(GenesisAnchorError::AnchorMismatch {
                    voter_node_id: self.node_id.clone(),
                    group_id: group_id.to_string(),
                }
                .into());
            }
        } else {
            state.trusted_genesis_digest = Some(genesis_digest.clone());
        }
        if let Some(existing) = state.installed_epochs.get(&1) {
            if existing != &cfg {
                anyhow::bail!(
                    "Conflicting genesis epoch-1 configuration on voter '{}' for '{}'",
                    self.node_id,
                    group_id
                );
            }
            return Ok(genesis_digest);
        }
        state.installed_epochs.insert(1, cfg);
        if state.min_active_epoch == 0 {
            state.min_active_epoch = 1;
        }
        self.persist_term_state(&state).await?;
        Ok(genesis_digest)
    }

    /// Verify and install a membership-transition chain (`1 -> 2 -> ... -> N`) on a newly admitted
    /// voter strictly against its **independently provisioned** local `trusted_genesis_digest`
    /// (established via `set_trusted_genesis_anchor()` or `install_genesis_epoch()`).
    ///
    /// Never creates or replaces a trust anchor from caller-supplied chain data; returns typed
    /// `GenesisAnchorError::MissingTrustedGenesisAnchor` on an uninitialized voter!
    pub async fn install_membership_chain_from_genesis(
        &self,
        group_id: &str,
        genesis_mode: ConsensusMode,
        genesis_members: Vec<GroupMember>,
        transitions: &[MembershipTransitionDecision],
    ) -> Result<u64> {
        let pinned = {
            let _tx = self.db.lock_tx().await;
            let state = self.load_term_state(group_id).await?;
            match state.and_then(|s| s.trusted_genesis_digest) {
                Some(d) => d,
                None => {
                    return Err(GenesisAnchorError::MissingTrustedGenesisAnchor {
                        voter_node_id: self.node_id.clone(),
                        group_id: group_id.to_string(),
                    }
                    .into());
                }
            }
        };
        let computed = hash_genesis_config(group_id, genesis_mode, &genesis_members)?;
        if computed != pinned {
            return Err(GenesisAnchorError::AnchorMismatch {
                voter_node_id: self.node_id.clone(),
                group_id: group_id.to_string(),
            }
            .into());
        }
        let _ = self
            .install_genesis_epoch(group_id, genesis_mode, genesis_members.clone())
            .await?;

        let mut prev_cfg = MembershipEpochConfig {
            mode: genesis_mode,
            members: genesis_members
                .into_iter()
                .map(|m| (m.node_id.clone(), m))
                .collect(),
        };
        let mut cur_epoch = 1u64;
        for dec in transitions {
            if dec.proposal.group_id != group_id
                || dec.proposal.prev_epoch != cur_epoch
                || dec.proposal.next_epoch != cur_epoch + 1
            {
                anyhow::bail!(
                    "Non-consecutive or mismatched transition in bootstrap chain on '{}': expected epoch {} -> {}",
                    self.node_id,
                    cur_epoch,
                    cur_epoch + 1
                );
            }
            let receipt = self.install_membership_epoch(dec, &prev_cfg).await?;
            if !receipt.post_transition_old_locks.is_empty() {
                anyhow::bail!(
                    "Bootstrap chain installation on '{}' blocked by {} unresolved post-transition old-epoch locks",
                    self.node_id,
                    receipt.post_transition_old_locks.len()
                );
            }
            cur_epoch = receipt.min_active_epoch;
            prev_cfg = MembershipEpochConfig {
                mode: dec.proposal.mode,
                members: dec
                    .proposal
                    .new_members
                    .iter()
                    .cloned()
                    .map(|m| (m.node_id.clone(), m))
                    .collect(),
            };
        }
        Ok(cur_epoch)
    }

    /// Explicit, idempotent, durable membership-epoch installation for voters that ALREADY hold
    /// a locally verified predecessor epoch (`prop.prev_epoch`).
    ///
    /// Atomically installs the old-epoch barrier (`epoch_barriers[prev_epoch] = prop.slot`),
    /// inspects & validates EVERY durable lock at `(prev_epoch, slot > prop.slot)` without
    /// deleting or overwriting them, and only advances `min_active_epoch` when no unresolved
    /// post-transition old-epoch locks exist!
    pub async fn install_membership_epoch(
        &self,
        decision: &MembershipTransitionDecision,
        prev_cfg: &MembershipEpochConfig,
    ) -> Result<EpochInstallReceipt> {
        let _tx = self.db.lock_tx().await;
        let prop = &decision.proposal;
        if prop.next_epoch != prop.prev_epoch.saturating_add(1) {
            anyhow::bail!(
                "Invalid membership epoch transition ({} -> {})",
                prop.prev_epoch,
                prop.next_epoch
            );
        }
        if prop.mode != prev_cfg.mode {
            anyhow::bail!(
                "Membership transition mode {:?} disagrees with predecessor mode {:?}",
                prop.mode,
                prev_cfg.mode
            );
        }

        let mut state = self.load_term_state(&prop.group_id).await?.ok_or_else(|| {
            anyhow!(
                "Voter '{}' has no trusted genesis/predecessor anchor for '{}'; provision anchor and use install_membership_chain_from_genesis()",
                self.node_id,
                prop.group_id
            )
        })?;
        let installed_prev = state.installed_epochs.get(&prop.prev_epoch).ok_or_else(|| {
            anyhow!(
                "Voter '{}' lacks locally verified predecessor epoch {} for '{}'; rejecting unanchored prev_cfg",
                self.node_id,
                prop.prev_epoch,
                prop.group_id
            )
        })?;
        if installed_prev != prev_cfg {
            anyhow::bail!(
                "Supplied prev_cfg disagrees with voter '{}' locally verified epoch {} configuration",
                self.node_id,
                prop.prev_epoch
            );
        }

        let expected_digest = prop.canonical_digest()?;
        if decision.qc.group_id != prop.group_id
            || decision.qc.epoch != prop.prev_epoch
            || decision.qc.slot != prop.slot
            || decision.qc.mode != prev_cfg.mode
            || decision.qc.proposal_hash != expected_digest
        {
            anyhow::bail!("MembershipTransitionDecision QC header/digest mismatch");
        }
        let mut unique_voters = HashSet::new();
        for v in &decision.qc.votes {
            if v.group_id != decision.qc.group_id
                || v.epoch != decision.qc.epoch
                || v.term != decision.qc.term
                || v.slot != decision.qc.slot
                || v.proposal_hash != decision.qc.proposal_hash
            {
                anyhow::bail!("MembershipTransitionDecision QC contains mismatched vote");
            }
            let member = prev_cfg.members.get(&v.voter_node_id).ok_or_else(|| {
                anyhow!(
                    "MembershipTransitionDecision voter '{}' not authorized in epoch {}",
                    v.voter_node_id,
                    prop.prev_epoch
                )
            })?;
            let payload = canonical_vote_payload_for_term(
                &v.group_id,
                v.epoch,
                v.term,
                v.slot,
                &v.proposal_hash,
                &v.voter_node_id,
            );
            if !nexus_db::auth::ed25519_verify(&member.ed25519_pubkey, &payload, &v.signature) {
                anyhow::bail!(
                    "Invalid Ed25519 signature from '{}' on MembershipTransitionDecision",
                    v.voter_node_id
                );
            }
            unique_voters.insert(v.voter_node_id.clone());
        }
        let required = prev_cfg.mode.quorum_size(prev_cfg.members.len());
        if unique_voters.len() < required {
            anyhow::bail!(
                "Insufficient quorum on MembershipTransitionDecision: got {}, need {}",
                unique_voters.len(),
                required
            );
        }

        // Inspect & cryptographically validate ALL pre-existing durable locks at
        // `(prop.group_id, self.node_id, epoch == prop.prev_epoch, slot > prop.slot)`.
        // NEVER delete or overwrite them; preserve complete evidence for recovery!
        let mut lresp = self
            .db
            .client
            .query("SELECT * FROM sys_mesh_voter_lock")
            .await?;
        let lrows: Vec<serde_json::Value> = lresp.take(0).unwrap_or_default();
        let mut post_transition_old_locks = Vec::new();
        for raw in lrows {
            if let Some(gid) = raw.get("group_id").and_then(|v| v.as_str()) {
                if gid != prop.group_id {
                    continue;
                }
            }
            if let Some(vid) = raw.get("voter_node_id").and_then(|v| v.as_str()) {
                if vid != self.node_id {
                    continue;
                }
            }
            let lock: DurableVoterLock = serde_json::from_value(raw).map_err(|e| {
                anyhow!(
                    "Corrupt durable voter lock on '{}' during epoch installation: {}",
                    self.node_id,
                    e
                )
            })?;
            if lock.group_id != prop.group_id
                || lock.voter_node_id != self.node_id
                || lock.epoch != prop.prev_epoch
                || lock.slot <= prop.slot
            {
                continue;
            }
            let expected_lk = self.slot_lock_key(&lock.group_id, lock.epoch, lock.slot);
            if lock.lock_key != expected_lk {
                anyhow::bail!("Misbound post-transition lock_key on '{}'", self.node_id);
            }
            let lock_prop = lock.proposal.ok_or_else(|| {
                anyhow!(
                    "Incomplete post-transition old-epoch lock on '{}' at slot {} (missing SlotProposal)",
                    self.node_id,
                    lock.slot
                )
            })?;
            let computed = lock_prop.validate_for_vote(&lock.group_id, lock.epoch, lock.slot)?;
            if computed != lock.proposal_hash {
                anyhow::bail!(
                    "Tampered post-transition old-epoch lock on '{}' at slot {}",
                    self.node_id,
                    lock.slot
                );
            }
            if let Some(self_member) = prev_cfg.members.get(&self.node_id) {
                let vpayload = canonical_vote_payload_for_term(
                    &lock.group_id,
                    lock.epoch,
                    lock.accepted_term,
                    lock.slot,
                    &lock.proposal_hash,
                    &lock.voter_node_id,
                );
                if !nexus_db::auth::ed25519_verify(&self_member.ed25519_pubkey, &vpayload, &lock.signature) {
                    anyhow::bail!(
                        "Invalid Ed25519 signature on post-transition old-epoch lock at slot {}",
                        lock.slot
                    );
                }
            }
            let vote = SignedVote {
                group_id: lock.group_id,
                epoch: lock.epoch,
                term: lock.accepted_term,
                slot: lock.slot,
                proposal_hash: lock.proposal_hash.clone(),
                voter_node_id: lock.voter_node_id,
                signature: lock.signature,
            };
            post_transition_old_locks.push(AcceptedSlotLock {
                epoch: lock.epoch,
                slot: lock.slot,
                accepted_term: lock.accepted_term,
                proposal_hash: lock.proposal_hash,
                proposal: lock_prop,
                vote,
            });
        }
        post_transition_old_locks.sort_by_key(|l| (l.slot, l.accepted_term));

        // Always persist the durable old-epoch barrier (`epoch_barriers[prev_epoch] <= prop.slot`)
        // so NO further old-epoch votes beyond `prop.slot` can ever be accepted!
        state
            .epoch_barriers
            .entry(prop.prev_epoch)
            .and_modify(|b| *b = (*b).min(prop.slot))
            .or_insert(prop.slot);

        // Only advance `min_active_epoch` & install `next_epoch` if NO unresolved post-transition
        // old-epoch locks exist on this voter!
        if post_transition_old_locks.is_empty() {
            let new_cfg = MembershipEpochConfig {
                mode: prop.mode,
                members: prop
                    .new_members
                    .iter()
                    .cloned()
                    .map(|m| (m.node_id.clone(), m))
                    .collect(),
            };
            if let Some(existing_next) = state.installed_epochs.get(&prop.next_epoch) {
                if existing_next != &new_cfg {
                    anyhow::bail!(
                        "Conflicting epoch {} configuration already installed on voter '{}'",
                        prop.next_epoch,
                        self.node_id
                    );
                }
            } else {
                state.installed_epochs.insert(prop.next_epoch, new_cfg);
            }
            state.min_active_epoch = state.min_active_epoch.max(prop.next_epoch);
        }

        self.persist_term_state(&state).await?;
        Ok(EpochInstallReceipt {
            voter_node_id: self.node_id.clone(),
            min_active_epoch: state.min_active_epoch,
            barrier_slot: prop.slot,
            post_transition_old_locks,
        })
    }

    /// Atomic Phase-1 durable term promise + linearizable accepted-lock snapshot:
    /// - Serialized across all `VoterNode` handles sharing `self.db` (`self.db.lock_tx()`) AND
    ///   backed by DB-atomic conditional `UPDATE ... WHERE` in `nexus-db`.
    /// - Lower terms can never replace higher terms; a term can be promised to at most one leader;
    ///   same-term same-leader retries are idempotent; accepted locks are read at the exact
    ///   linearization point so no concurrent `cast_vote()` can interleave!
    pub async fn prepare_term(&self, req: &PrepareTermRequest) -> Result<TermPromise> {
        if req.term == 0 || req.leader_id.is_empty() {
            anyhow::bail!("PrepareTermRequest requires term >= 1 and non-empty leader_id");
        }
        let _tx = self.db.lock_tx().await;
        self.ensure_tables().await?;

        let state = self.load_term_state(&req.group_id).await?.ok_or_else(|| {
            anyhow!(
                "Voter '{}' has no installed membership configuration for '{}'; install genesis/chain first",
                self.node_id,
                req.group_id
            )
        })?;
        if req.epoch < state.min_active_epoch {
            anyhow::bail!(
                "Stale epoch {} rejected on voter '{}' (min_active_epoch={})",
                req.epoch,
                self.node_id,
                state.min_active_epoch
            );
        }
        let epoch_cfg = state.installed_epochs.get(&req.epoch).ok_or_else(|| {
            anyhow!(
                "Voter '{}' has not installed membership epoch {} certificate",
                self.node_id,
                req.epoch
            )
        })?;
        if !epoch_cfg.members.contains_key(&self.node_id) {
            anyhow::bail!(
                "Removed voter '{}' cannot participate in epoch {}",
                self.node_id,
                req.epoch
            );
        }

        // Atomic conditional UPDATE in nexus-db (monotonically advances promised_term OR allows
        // exact same-term same-leader idempotent retry; rejects lower term or rival leader!)
        let tkey = self.term_state_key(&req.group_id);
        let mut upd = self
            .db
            .client
            .query(
                "UPDATE type::record('sys_mesh_voter_term', $id) \
                 SET promised_term = $term, promised_leader_id = $leader \
                 WHERE min_active_epoch <= $epoch \
                   AND (promised_term < $term OR (promised_term == $term AND promised_leader_id == $leader));",
            )
            .bind(("id", tkey))
            .bind(("term", req.term))
            .bind(("leader", req.leader_id.clone()))
            .bind(("epoch", req.epoch))
            .await?;
        let updated_rows: Vec<serde_json::Value> = upd.take(0).unwrap_or_default();
        let committed_raw = updated_rows.first().ok_or_else(|| {
            anyhow!(
                "Atomic term promise rejected on voter '{}' for (group={}, epoch={}, term={}, leader={}): stale epoch/term or term already promised to another leader",
                self.node_id,
                req.group_id,
                req.epoch,
                req.term,
                req.leader_id
            )
        })?;
        let committed_state: DurableVoterTermState =
            serde_json::from_value(committed_raw.clone()).map_err(|e| {
                anyhow!("Failed to parse committed voter term state: {}", e)
            })?;

        // Collect all durable accepted locks at this EXACT linearization point (inside `_tx`!)
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM sys_mesh_voter_lock")
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let mut accepted_locks = Vec::new();
        for raw in rows {
            if let Some(gid) = raw.get("group_id").and_then(|v| v.as_str()) {
                if gid != req.group_id {
                    continue;
                }
            }
            if let Some(vid) = raw.get("voter_node_id").and_then(|v| v.as_str()) {
                if vid != self.node_id {
                    continue;
                }
            }
            let lock: DurableVoterLock = serde_json::from_value(raw).map_err(|e| {
                anyhow!(
                    "Corrupt durable voter lock on '{}' during prepare_term: {}",
                    self.node_id,
                    e
                )
            })?;
            if lock.group_id != req.group_id || lock.voter_node_id != self.node_id {
                continue;
            }
            if lock.epoch != req.epoch || lock.slot < req.from_slot {
                continue;
            }
            let expected_lk = self.slot_lock_key(&lock.group_id, lock.epoch, lock.slot);
            if lock.lock_key != expected_lk {
                anyhow::bail!("Misbound lock_key on voter '{}' during prepare_term", self.node_id);
            }
            let prop = lock.proposal.ok_or_else(|| {
                anyhow!(
                    "Incomplete durable voter lock on '{}' at slot {} (missing SlotProposal)",
                    self.node_id,
                    lock.slot
                )
            })?;
            let vote = SignedVote {
                group_id: lock.group_id,
                epoch: lock.epoch,
                term: lock.accepted_term,
                slot: lock.slot,
                proposal_hash: lock.proposal_hash.clone(),
                voter_node_id: lock.voter_node_id,
                signature: lock.signature,
            };
            accepted_locks.push(AcceptedSlotLock {
                epoch: lock.epoch,
                slot: lock.slot,
                accepted_term: lock.accepted_term,
                proposal_hash: lock.proposal_hash,
                proposal: prop,
                vote,
            });
        }
        accepted_locks.sort_by_key(|l| (l.slot, l.accepted_term));

        let payload = canonical_promise_payload(
            &req.group_id,
            req.epoch,
            committed_state.promised_term,
            &req.leader_id,
            req.from_slot,
            &self.node_id,
            committed_state.min_active_epoch,
            &accepted_locks,
        );
        let signature = nexus_db::auth::ed25519_sign(&self.ed25519_sk_b64, &payload)?;
        Ok(TermPromise {
            group_id: req.group_id.clone(),
            epoch: req.epoch,
            term: committed_state.promised_term,
            leader_id: req.leader_id.clone(),
            from_slot: req.from_slot,
            voter_node_id: self.node_id.clone(),
            min_active_epoch: committed_state.min_active_epoch,
            accepted_locks,
            signature,
        })
    }

    pub fn slot_lock_key(&self, group_id: &str, epoch: u64, slot: u64) -> String {
        format!(
            "{}_{}_{}_{}",
            &blake3::hash(group_id.as_bytes()).to_hex().as_str()[..12],
            epoch,
            slot,
            self.node_id
        )
    }

    /// Query this voter's durable lock (both `SignedVote` and canonical `Option<SlotProposal>`).
    ///
    /// Preserves the strict distinction between an absent lock (`Ok(None)`) and a corrupt or
    /// unreadable lock record (`Err(...)`).
    pub async fn query_slot_lock(
        &self,
        group_id: &str,
        epoch: u64,
        slot: u64,
    ) -> Result<Option<(SignedVote, Option<SlotProposal>)>> {
        self.ensure_tables().await?;
        let lock_key = self.slot_lock_key(group_id, epoch, slot);
        let mut resp = self
            .db
            .client
            .query("SELECT * FROM type::record('sys_mesh_voter_lock', $id)")
            .bind(("id", lock_key.clone()))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let Some(raw) = rows.first() else {
            return Ok(None);
        };
        let existing: DurableVoterLock = serde_json::from_value(raw.clone()).map_err(|e| {
            anyhow!(
                "Corrupt or malformed durable voter lock on '{}' for ({}, epoch={}, slot={}): {}",
                self.node_id,
                group_id,
                epoch,
                slot,
                e
            )
        })?;
        if existing.lock_key != lock_key
            || existing.group_id != group_id
            || existing.epoch != epoch
            || existing.slot != slot
            || existing.voter_node_id != self.node_id
        {
            anyhow::bail!(
                "Misbound durable voter lock on '{}': lookup=(key={}, group={}, epoch={}, slot={}), stored=(key={}, group={}, epoch={}, slot={}, voter={})",
                self.node_id,
                lock_key,
                group_id,
                epoch,
                slot,
                existing.lock_key,
                existing.group_id,
                existing.epoch,
                existing.slot,
                existing.voter_node_id
            );
        }
        Ok(Some((
            SignedVote {
                group_id: existing.group_id,
                epoch: existing.epoch,
                term: existing.accepted_term,
                slot: existing.slot,
                proposal_hash: existing.proposal_hash,
                voter_node_id: existing.voter_node_id,
                signature: existing.signature,
            },
            existing.proposal,
        )))
    }

    /// Require canonical `SlotProposal`, enforce durable term & epoch fencing, independently verify
    /// Phase-1 `TermCertificate` & Paxos value-adoption rules for all term-fenced (`term >= 1`)
    /// votes, and atomically persist the durable lock BEFORE returning the signature!
    pub async fn cast_vote(&self, req: &VoteRequest) -> Result<SignedVote> {
        let req_prop = req.proposal.as_ref().ok_or_else(|| {
            anyhow!(
                "Production VoteRequest for ({}, epoch={}, slot={}) requires a canonical SlotProposal payload",
                req.group_id,
                req.epoch,
                req.slot
            )
        })?;
        let computed = req_prop.validate_for_vote(&req.group_id, req.epoch, req.slot)?;
        if computed != req.proposal_hash {
            anyhow::bail!(
                "Proposal payload digest '{}' does not match claimed proposal_hash '{}'",
                computed,
                req.proposal_hash
            );
        }

        if req.term == 0 && !self.allow_legacy_term_zero {
            anyhow::bail!(
                "Production VoterNode '{}' rejects term-0 VoteRequest: require installed membership config, term >= 1, and verifiable Phase-1 TermCertificate",
                self.node_id
            );
        }

        let _tx = self.db.lock_tx().await;
        self.ensure_tables().await?;
        let term_state_opt = self.load_term_state(&req.group_id).await?;

        // Enforce voter-side epoch & term fencing + independent Phase-1 adoption proof!
        if req.term > 0 {
            let state = term_state_opt.as_ref().ok_or_else(|| {
                anyhow!(
                    "Voter '{}' has no active term promise for '{}'; Phase-1 prepare_term required",
                    self.node_id,
                    req.group_id
                )
            })?;
            if req.epoch < state.min_active_epoch {
                anyhow::bail!(
                    "Stale epoch {} rejected on voter '{}' (min_active_epoch={})",
                    req.epoch,
                    self.node_id,
                    state.min_active_epoch
                );
            }
            if let Some(&barrier_slot) = state.epoch_barriers.get(&req.epoch) {
                if req.slot > barrier_slot {
                    anyhow::bail!(
                        "Durable old-epoch log barrier at slot {} on voter '{}' fences vote for ({}, epoch={}, slot={})",
                        barrier_slot,
                        self.node_id,
                        req.group_id,
                        req.epoch,
                        req.slot
                    );
                }
            }
            let epoch_cfg = state.installed_epochs.get(&req.epoch).ok_or_else(|| {
                anyhow!(
                    "Voter '{}' has not installed membership configuration for epoch {}",
                    self.node_id,
                    req.epoch
                )
            })?;
            if !epoch_cfg.members.contains_key(&self.node_id) {
                anyhow::bail!(
                    "Removed voter '{}' cannot vote in epoch {}",
                    self.node_id,
                    req.epoch
                );
            }
            let req_leader = req.leader_id.as_deref().ok_or_else(|| {
                anyhow!("Term-fenced VoteRequest (term={}) requires leader_id", req.term)
            })?;
            if req.term != state.promised_term
                || state.promised_leader_id.as_deref() != Some(req_leader)
            {
                anyhow::bail!(
                    "VoteRequest (term={}, leader={}) does not match active promise (term={}, leader={:?}) on voter '{}'",
                    req.term,
                    req_leader,
                    state.promised_term,
                    state.promised_leader_id,
                    self.node_id
                );
            }
            let cert = req.term_cert.as_ref().ok_or_else(|| {
                anyhow!(
                    "Higher-term VoteRequest (term={}) rejected: missing verifiable Phase-1 TermCertificate",
                    req.term
                )
            })?;
            if cert.group_id != req.group_id
                || cert.epoch != req.epoch
                || cert.term != req.term
                || cert.leader_id != req_leader
            {
                anyhow::bail!("TermCertificate does not match VoteRequest (group/epoch/term/leader)");
            }
            // Independently verify Phase-1 quorum AND Paxos value-adoption invariant!
            if let Some(adopted) = verify_term_certificate_and_adoption(cert, epoch_cfg, req.slot)? {
                if &adopted != req_prop {
                    anyhow::bail!(
                        "Paxos adoption violation on voter '{}' at slot {} (term={}): VoteRequest conflicts with highest-term adopted proposal!",
                        self.node_id,
                        req.slot,
                        req.term
                    );
                }
            }
        } else if let Some(ref state) = term_state_opt {
            if req.epoch < state.min_active_epoch {
                anyhow::bail!(
                    "Stale epoch {} rejected on voter '{}' (min_active_epoch={})",
                    req.epoch,
                    self.node_id,
                    state.min_active_epoch
                );
            }
            if let Some(&barrier_slot) = state.epoch_barriers.get(&req.epoch) {
                if req.slot > barrier_slot {
                    anyhow::bail!(
                        "Durable old-epoch log barrier at slot {} on voter '{}' fences vote for ({}, epoch={}, slot={})",
                        barrier_slot,
                        self.node_id,
                        req.group_id,
                        req.epoch,
                        req.slot
                    );
                }
            }
            if state.promised_term > 0 {
                anyhow::bail!(
                    "Unfenced term-0 VoteRequest rejected on voter '{}' (promised_term={})",
                    self.node_id,
                    state.promised_term
                );
            }
        }

        let lock_key = self.slot_lock_key(&req.group_id, req.epoch, req.slot);
        let vote = sign_vote_raw_in_term(
            &req.group_id,
            req.epoch,
            req.term,
            req.slot,
            &req.proposal_hash,
            &self.node_id,
            &self.ed25519_sk_b64,
        )?;
        let lock_rec = DurableVoterLock {
            lock_key: lock_key.clone(),
            group_id: req.group_id.clone(),
            epoch: req.epoch,
            accepted_term: req.term,
            slot: req.slot,
            proposal_hash: req.proposal_hash.clone(),
            proposal: Some(req_prop.clone()),
            voter_node_id: self.node_id.clone(),
            signature: vote.signature.clone(),
            locked_at_ms: now_ms(),
        };
        let val = serde_json::to_value(&lock_rec)?;

        // When accepting a `SlotProposal::Membership`, persist BOTH the durable vote lock AND the
        // durable old-epoch barrier (`epoch_barriers[req.epoch] <= req.slot`) atomically inside
        // ONE `nexus-db` transaction so there is ZERO crash window between acceptance and fencing!
        let barrier_state_update: Option<(String, serde_json::Value)> =
            if matches!(req_prop, SlotProposal::Membership(_)) {
                if let Some(mut ts) = term_state_opt.clone() {
                    ts.epoch_barriers
                        .entry(req.epoch)
                        .and_modify(|b| *b = (*b).min(req.slot))
                        .or_insert(req.slot);
                    Some((ts.term_key.clone(), serde_json::to_value(&ts)?))
                } else {
                    None
                }
            } else {
                None
            };

        let create_res = if let Some((ref tid, ref ts_val)) = barrier_state_update {
            self.db
                .client
                .query(
                    "BEGIN TRANSACTION;\
                     CREATE type::record('sys_mesh_voter_lock', $id) CONTENT $l;\
                     UPSERT type::record('sys_mesh_voter_term', $tid) CONTENT $ts;\
                     COMMIT TRANSACTION;",
                )
                .bind(("id", lock_key.clone()))
                .bind(("l", val.clone()))
                .bind(("tid", tid.clone()))
                .bind(("ts", ts_val.clone()))
                .await
        } else {
            self.db
                .client
                .query("CREATE type::record('sys_mesh_voter_lock', $id) CONTENT $l;")
                .bind(("id", lock_key.clone()))
                .bind(("l", val.clone()))
                .await
        };

        match create_res {
            Ok(resp) => match resp.check() {
                Ok(_) => return Ok(vote),
                Err(e) if is_already_exists_error(&e) => {}
                Err(e) => return Err(anyhow!("Failed to persist voter lock: {}", e)),
            },
            Err(e) if is_already_exists_error(&e) => {}
            Err(e) => return Err(anyhow!("Database error persisting voter lock: {}", e)),
        }

        // Existing lock found: read back & validate identity!
        let (existing_vote, existing_prop) = self
            .query_slot_lock(&req.group_id, req.epoch, req.slot)
            .await?
            .ok_or_else(|| anyhow!("Voter lock reported existing but could not be read back"))?;

        if req.term < existing_vote.term {
            anyhow::bail!(
                "Stale-term VoteRequest (term={}) rejected on voter '{}': slot {} already accepted at term {}",
                req.term,
                self.node_id,
                req.slot,
                existing_vote.term
            );
        }

        if req.term > existing_vote.term {
            // Reject payload-less legacy locks BEFORE starting any replacement transaction
            // so a failing request can never install a barrier independently!
            if existing_prop.is_none() {
                anyhow::bail!(
                    "Cannot overwrite legacy payload-less lock on '{}' at slot {}",
                    self.node_id,
                    req.slot
                );
            }

            // Higher term with verified Phase-1 TermCertificate & adoption proof:
            // Execute conditional lock replacement AND (for Membership proposals) durable old-epoch
            // barrier update inside ONE atomic `nexus-db` transaction!
            let prop_val = serde_json::to_value(req_prop)?;
            if let Some((tid, ts_val)) = barrier_state_update {
                let bindings = vec![
                    ("id".to_string(), nexus_db::Value::String(lock_key.clone())),
                    ("term".to_string(), nexus_db::Value::Int(req.term as i64)),
                    ("ph".to_string(), nexus_db::Value::String(req.proposal_hash.clone())),
                    ("prop".to_string(), nexus_db::Value::from_json(&prop_val)),
                    ("sig".to_string(), nexus_db::Value::String(vote.signature.clone())),
                    ("now".to_string(), nexus_db::Value::Int(now_ms() as i64)),
                    ("tid".to_string(), nexus_db::Value::String(tid)),
                    ("ts".to_string(), nexus_db::Value::from_json(&ts_val)),
                ];
                let outcomes = self.db.inner.query_scoped_multi(
                    "nexus",
                    "system",
                    "BEGIN TRANSACTION;\
                     UPDATE type::record('sys_mesh_voter_lock', $id) \
                       SET accepted_term = $term, proposal_hash = $ph, proposal = $prop, signature = $sig, locked_at_ms = $now \
                       WHERE accepted_term < $term AND proposal != NONE;\
                     UPSERT type::record('sys_mesh_voter_term', $tid) CONTENT $ts;\
                     COMMIT TRANSACTION;",
                    bindings,
                )?;
                let lock_updated_count = outcomes.get(1).map(|o| o.result.len()).unwrap_or(0);
                if lock_updated_count == 1 {
                    return Ok(vote);
                }
            } else {
                let mut upd = self
                    .db
                    .client
                    .query(
                        "UPDATE type::record('sys_mesh_voter_lock', $id) \
                         SET accepted_term = $term, proposal_hash = $ph, proposal = $prop, signature = $sig, locked_at_ms = $now \
                         WHERE accepted_term < $term AND proposal != NONE;",
                    )
                    .bind(("id", lock_key))
                    .bind(("term", req.term))
                    .bind(("ph", req.proposal_hash.clone()))
                    .bind(("prop", prop_val))
                    .bind(("sig", vote.signature.clone()))
                    .bind(("now", now_ms()))
                    .await?;
                let updated_rows: Vec<serde_json::Value> = upd.take(0).unwrap_or_default();
                if updated_rows.len() == 1 {
                    return Ok(vote);
                }
            }

            // Conditional UPDATE lost a race: re-read committed lock and accept ONLY on strict exact equality!
            let (committed_vote, committed_prop) = self
                .query_slot_lock(&req.group_id, req.epoch, req.slot)
                .await?
                .ok_or_else(|| anyhow!("Voter lock vanished after conditional UPDATE"))?;
            if committed_vote.term == req.term
                && committed_vote.proposal_hash == req.proposal_hash
                && committed_prop.as_ref() == Some(req_prop)
            {
                return Ok(committed_vote);
            }
            anyhow::bail!(
                "Atomic higher-term slot-lock replacement lost/rejected on '{}' at slot {} (committed_term={}, requested_term={})",
                self.node_id,
                req.slot,
                committed_vote.term,
                req.term
            );
        }

        // Same term: require STRICT equality of BOTH proposal_hash AND canonical proposal!
        // Legacy locks (`existing_prop == None`) are NEVER upgraded or accepted on retry.
        if existing_vote.proposal_hash == req.proposal_hash {
            if existing_prop.as_ref() != Some(req_prop) {
                anyhow::bail!(
                    "Strict voter-lock mismatch on node '{}' for ({}, epoch={}, slot={}): existing proposal payload does not equal requested proposal (legacy locks cannot be upgraded)",
                    self.node_id,
                    req.group_id,
                    req.epoch,
                    req.slot
                );
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
    pub current_term: u64,
    pub active_term_cert: Option<TermCertificate>,
    pub next_slot: u64,
    pub max_lease_ttl_ms: u64,
    pub members: HashMap<String, GroupMember>,
    /// Durable per-epoch membership snapshots so historical decisions validate against their
    /// original membership epoch even after subsequent reconfigurations.
    pub membership_history: HashMap<u64, MembershipEpochConfig>,
    pub active_leases: HashMap<String, FencedLease>,
    pub max_fencing_epoch: HashMap<String, u64>,
    seen_votes: HashMap<(u64, u64, String), SignedVote>,
    pub equivocations: Vec<EquivocationProof>,
    db: Option<Arc<Database>>,
}

impl CoordinationGroup {
    pub fn new(group_id: impl Into<String>, mode: ConsensusMode, members: Vec<GroupMember>) -> Self {
        let map: HashMap<String, GroupMember> = members
            .into_iter()
            .map(|m| (m.node_id.clone(), m))
            .collect();
        let mut membership_history = HashMap::new();
        membership_history.insert(
            1,
            MembershipEpochConfig {
                mode,
                members: map.clone(),
            },
        );
        Self {
            group_id: group_id.into(),
            mode,
            membership_epoch: 1,
            current_term: 0,
            active_term_cert: None,
            next_slot: 1,
            max_lease_ttl_ms: 300_000,
            members: map,
            membership_history,
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
            DEFINE TABLE IF NOT EXISTS sys_mesh_membership_history SCHEMALESS;\
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
        let active_mem_opt: Option<DurableMembershipRecord> = if let Some(raw_mem) = mrows.first() {
            let rec: DurableMembershipRecord = serde_json::from_value(raw_mem.clone())
                .map_err(|e| anyhow!("Malformed durable membership record for '{}': {}", gid, e))?;
            if rec.group_id != gid {
                anyhow::bail!(
                    "Durable membership record group_id '{}' does not match expected '{}'",
                    rec.group_id,
                    gid
                );
            }
            Some(rec)
        } else {
            None
        };

        // Load ALL durable membership epoch history records for this group (fail closed on malformed!)
        let mut hresp = db.client.query("SELECT * FROM sys_mesh_membership_history").await?;
        let hrows: Vec<serde_json::Value> = hresp.take(0).unwrap_or_default();
        let mut history_by_epoch: HashMap<u64, DurableMembershipEpochRecord> = HashMap::new();
        for v in hrows {
            if let Some(row_gid) = v.get("group_id").and_then(|g| g.as_str()) {
                if row_gid != gid {
                    continue;
                }
            }
            let rec: DurableMembershipEpochRecord = serde_json::from_value(v).map_err(|e| {
                anyhow!("Malformed durable membership history record for '{}': {}", gid, e)
            })?;
            if rec.group_id != gid {
                continue;
            }
            if history_by_epoch.insert(rec.membership_epoch, rec).is_some() {
                anyhow::bail!(
                    "Duplicate durable membership history record for '{}'",
                    gid
                );
            }
        }

        let mut min_safe_next_slot: u64 = 1;
        let mut active_next_slot_for_check: Option<u64> = None;

        match (active_mem_opt, history_by_epoch.is_empty()) {
            (None, true) => {
                // Before initializing genesis, verify NO existing or ambiguous decision-log rows exist!
                // Ignore a record ONLY when its group_id is positively established as another group.
                let mut pre_lresp = db.client.query("SELECT * FROM sys_mesh_decision_log").await?;
                let pre_lrows: Vec<serde_json::Value> = pre_lresp.take(0).unwrap_or_default();
                for v in pre_lrows {
                    match decision_row_group_id(&v) {
                        Some(row_gid) if row_gid != gid => continue,
                        Some(_) => {
                            anyhow::bail!(
                                "Cannot initialize genesis for '{}': existing decision-log record found without durable membership state",
                                gid
                            );
                        }
                        None => {
                            anyhow::bail!(
                                "Cannot initialize genesis for '{}': malformed/ambiguous decision-log record without group_id prevents safe genesis initialization",
                                gid
                            );
                        }
                    }
                }
                // Brand-new group: initialize genesis epoch 1 atomically!
                if group.members.is_empty() {
                    anyhow::bail!("Cannot initialize coordination group '{}' with empty members", gid);
                }
                let mut mems: Vec<GroupMember> = group.members.values().cloned().collect();
                mems.sort_by(|a, b| a.node_id.cmp(&b.node_id));
                group.persist_genesis_atomic(&mems).await?;
            }
            (None, false) => {
                anyhow::bail!(
                    "Corrupt durable state for '{}': membership history exists without active sys_mesh_membership record",
                    gid
                );
            }
            (Some(_), true) => {
                anyhow::bail!(
                    "Corrupt durable state for '{}': active sys_mesh_membership exists without verifiable membership history",
                    gid
                );
            }
            (Some(active_rec), false) => {
                // Reconstruct and cryptographically verify the ENTIRE membership chain 1 -> 2 -> ... -> max_epoch!
                let max_epoch = *history_by_epoch.keys().max().unwrap_or(&0);
                if max_epoch == 0 {
                    anyhow::bail!("Invalid membership history epoch 0 for '{}'", gid);
                }
                group.membership_history.clear();
                for ep in 1..=max_epoch {
                    let rec = history_by_epoch.get(&ep).ok_or_else(|| {
                        anyhow!(
                            "Skipped or missing membership epoch {} in durable chain for '{}' (max={})",
                            ep,
                            gid,
                            max_epoch
                        )
                    })?;
                    if rec.members.is_empty() {
                        anyhow::bail!("Epoch {} in '{}' has empty member set", ep, gid);
                    }
                    let mut rec_sorted = rec.members.clone();
                    rec_sorted.sort_by(|a, b| a.node_id.cmp(&b.node_id));
                    let mut seen_ids = HashSet::new();
                    for m in &rec_sorted {
                        if !seen_ids.insert(m.node_id.as_str()) {
                            anyhow::bail!("Duplicate member '{}' in epoch {} of '{}'", m.node_id, ep, gid);
                        }
                    }

                    if ep == 1 {
                        if rec.transition.is_some() {
                            anyhow::bail!("Genesis epoch 1 in '{}' must not carry a transition certificate", gid);
                        }
                    } else {
                        let dec = rec.transition.as_ref().ok_or_else(|| {
                            anyhow!(
                                "Unproven membership epoch {} in '{}': missing MembershipTransitionDecision",
                                ep,
                                gid
                            )
                        })?;
                        let prev_cfg = group.membership_history.get(&(ep - 1)).ok_or_else(|| {
                            anyhow!("Missing verified predecessor epoch {} for '{}'", ep - 1, gid)
                        })?;
                        group.validate_membership_transition_against_prev(dec, prev_cfg, ep - 1, None)?;
                        if rec.mode != dec.proposal.mode {
                            anyhow::bail!(
                                "Epoch {} record mode {:?} disagrees with verified transition mode {:?}",
                                ep,
                                rec.mode,
                                dec.proposal.mode
                            );
                        }
                        let mut prop_sorted = dec.proposal.new_members.clone();
                        prop_sorted.sort_by(|a, b| a.node_id.cmp(&b.node_id));
                        if rec_sorted != prop_sorted {
                            anyhow::bail!(
                                "Epoch {} member set disagrees with verified MembershipTransitionProposal",
                                ep
                            );
                        }
                        min_safe_next_slot = min_safe_next_slot.max(dec.proposal.slot.saturating_add(1));
                    }

                    let members_map: HashMap<String, GroupMember> = rec_sorted
                        .into_iter()
                        .map(|m| (m.node_id.clone(), m))
                        .collect();
                    group.membership_history.insert(
                        ep,
                        MembershipEpochConfig {
                            mode: rec.mode,
                            members: members_map,
                        },
                    );
                }

                // Active membership record MUST match the verified chain tip EXACTLY!
                let tip_cfg = group
                    .membership_history
                    .get(&max_epoch)
                    .ok_or_else(|| anyhow!("Missing verified chain tip epoch {}", max_epoch))?;
                let mut active_sorted = active_rec.members.clone();
                active_sorted.sort_by(|a, b| a.node_id.cmp(&b.node_id));
                let mut tip_sorted: Vec<GroupMember> = tip_cfg.members.values().cloned().collect();
                tip_sorted.sort_by(|a, b| a.node_id.cmp(&b.node_id));
                if active_rec.membership_epoch != max_epoch
                    || active_rec.mode != tip_cfg.mode
                    || active_sorted != tip_sorted
                {
                    anyhow::bail!(
                        "Active sys_mesh_membership record for '{}' (epoch={}) disagrees with verified membership chain tip (epoch={})",
                        gid,
                        active_rec.membership_epoch,
                        max_epoch
                    );
                }
                group.mode = tip_cfg.mode;
                group.membership_epoch = max_epoch;
                group.current_term = active_rec.current_term;
                group.next_slot = active_rec.next_slot;
                group.members = tip_cfg.members.clone();
                active_next_slot_for_check = Some(active_rec.next_slot);
            }
        }

        // Load & cryptographically validate ALL durable slot decisions for this group (fail closed!)
        let mut lresp = db.client.query("SELECT * FROM sys_mesh_decision_log").await?;
        let lrows: Vec<serde_json::Value> = lresp.take(0).unwrap_or_default();
        for v in lrows {
            if let Some(row_gid) = decision_row_group_id(&v) {
                if row_gid != gid {
                    continue;
                }
            }
            let decision = parse_durable_slot_decision(v).map_err(|e| {
                anyhow!(
                    "Malformed durable decision record in sys_mesh_decision_log during boot of '{}': {}",
                    gid,
                    e
                )
            })?;
            group.validate_durable_slot_decision(&decision, None)?;
            min_safe_next_slot = min_safe_next_slot.max(decision.qc().slot.saturating_add(1));
            group.current_term = group.current_term.max(decision.qc().term);
            match decision {
                DurableSlotDecision::Lease(lease) => {
                    let cur_max = group.max_fencing_epoch.get(&lease.resource_key).copied().unwrap_or(0);
                    if lease.fencing_epoch > cur_max {
                        group.max_fencing_epoch.insert(lease.resource_key.clone(), lease.fencing_epoch);
                        group.active_leases.insert(lease.resource_key.clone(), lease.clone());
                    }
                }
                DurableSlotDecision::Membership(mdec) => {
                    // Ensure the corresponding historical epoch matches this decision
                    let Some(target_cfg) = group.membership_history.get(&mdec.proposal.next_epoch) else {
                        anyhow::bail!(
                            "Committed membership transition to epoch {} missing from verified history",
                            mdec.proposal.next_epoch
                        );
                    };
                    let mut prop_sorted = mdec.proposal.new_members.clone();
                    prop_sorted.sort_by(|a, b| a.node_id.cmp(&b.node_id));
                    let mut hist_sorted: Vec<GroupMember> = target_cfg.members.values().cloned().collect();
                    hist_sorted.sort_by(|a, b| a.node_id.cmp(&b.node_id));
                    if target_cfg.mode != mdec.proposal.mode || hist_sorted != prop_sorted {
                        anyhow::bail!(
                            "Committed membership decision for epoch {} disagrees with membership history",
                            mdec.proposal.next_epoch
                        );
                    }
                }
                DurableSlotDecision::NoOp(_) => {}
            }
        }

        // Validate active `next_slot` against EVERY verified transition & validated decision
        // without silently repairing a regressed slot counter!
        if let Some(active_next) = active_next_slot_for_check {
            if active_next < min_safe_next_slot {
                anyhow::bail!(
                    "Corrupt or regressed next_slot ({}) in sys_mesh_membership for '{}': verified committed history requires next_slot >= {}",
                    active_next,
                    gid,
                    min_safe_next_slot
                );
            }
        }
        Ok(group)
    }

    async fn persist_genesis_atomic(&self, members: &[GroupMember]) -> Result<()> {
        let Some(ref db) = self.db else { return Ok(()) };
        let gkey = blake3::hash(self.group_id.as_bytes()).to_hex().to_string();
        let hkey = membership_epoch_key(&self.group_id, 1);
        let rec = DurableMembershipRecord {
            group_id: self.group_id.clone(),
            mode: self.mode,
            membership_epoch: 1,
            current_term: self.current_term,
            next_slot: 1,
            members: members.to_vec(),
        };
        let hrec = DurableMembershipEpochRecord {
            group_id: self.group_id.clone(),
            membership_epoch: 1,
            mode: self.mode,
            members: members.to_vec(),
            transition: None,
        };
        let val = serde_json::to_value(&rec)?;
        let hval = serde_json::to_value(&hrec)?;
        db.client
            .query(
                "BEGIN TRANSACTION;\
                 CREATE type::record('sys_mesh_membership', $gkey) CONTENT $m;\
                 CREATE type::record('sys_mesh_membership_history', $hkey) CONTENT $h;\
                 COMMIT TRANSACTION;",
            )
            .bind(("gkey", gkey))
            .bind(("m", val))
            .bind(("hkey", hkey))
            .bind(("h", hval))
            .await?
            .check()?;
        Ok(())
    }

    /// Atomic 3-record membership-transition commit:
    /// `CREATE sys_mesh_decision_log:$skey` + `CREATE sys_mesh_membership_history:$hkey` +
    /// `UPSERT sys_mesh_membership:$gkey` inside ONE `nexus-db` transaction!
    ///
    /// On `DbError::AlreadyExists`, reads back AND cryptographically validates the existing durable
    /// records, accepting idempotently ONLY on exact verified digest/content match!
    async fn persist_membership_transition_atomic(
        &self,
        decision: &MembershipTransitionDecision,
        new_next_slot: u64,
    ) -> Result<()> {
        let Some(ref db) = self.db else { return Ok(()) };
        let prop = &decision.proposal;
        let skey = slot_decision_key(&prop.group_id, prop.prev_epoch, prop.slot);
        let hkey = membership_epoch_key(&prop.group_id, prop.next_epoch);
        let gkey = blake3::hash(self.group_id.as_bytes()).to_hex().to_string();

        let mut sorted_members = prop.new_members.clone();
        sorted_members.sort_by(|a, b| a.node_id.cmp(&b.node_id));

        let slot_dec = DurableSlotDecision::Membership(decision.clone());
        let dec_val = serde_json::to_value(&slot_dec)?;
        let hrec = DurableMembershipEpochRecord {
            group_id: prop.group_id.clone(),
            membership_epoch: prop.next_epoch,
            mode: prop.mode,
            members: sorted_members.clone(),
            transition: Some(decision.clone()),
        };
        let hval = serde_json::to_value(&hrec)?;
        let mrec = DurableMembershipRecord {
            group_id: prop.group_id.clone(),
            mode: prop.mode,
            membership_epoch: prop.next_epoch,
            current_term: self.current_term.max(decision.qc.term),
            next_slot: new_next_slot,
            members: sorted_members.clone(),
        };
        let mval = serde_json::to_value(&mrec)?;

        let tx_res = db
            .client
            .query(
                "BEGIN TRANSACTION;\
                 CREATE type::record('sys_mesh_decision_log', $skey) CONTENT $d;\
                 CREATE type::record('sys_mesh_membership_history', $hkey) CONTENT $h;\
                 UPSERT type::record('sys_mesh_membership', $gkey) CONTENT $m;\
                 COMMIT TRANSACTION;",
            )
            .bind(("skey", skey.clone()))
            .bind(("d", dec_val))
            .bind(("hkey", hkey.clone()))
            .bind(("h", hval))
            .bind(("gkey", gkey.clone()))
            .bind(("m", mval))
            .await;

        match tx_res {
            Ok(resp) => match resp.check() {
                Ok(_) => return Ok(()),
                Err(e) if is_already_exists_error(&e) => {}
                Err(e) => return Err(anyhow!("Failed atomic membership transition transaction: {}", e)),
            },
            Err(e) if is_already_exists_error(&e) => {}
            Err(e) => return Err(anyhow!("Database error in atomic membership transition: {}", e)),
        }

        // Duplicate detected: validate ALL THREE durable records (decision log, epoch history,
        // AND active membership tip/successor chain) before accepting an idempotent retry!
        let mut sresp = db
            .client
            .query("SELECT * FROM type::record('sys_mesh_decision_log', $skey)")
            .bind(("skey", skey))
            .await?;
        let srows: Vec<serde_json::Value> = sresp.take(0).unwrap_or_default();
        let raw_s = srows
            .first()
            .ok_or_else(|| anyhow!("Membership slot decision conflict reported but record missing"))?;
        let existing_slot = parse_durable_slot_decision(raw_s.clone())?;
        self.validate_durable_slot_decision(&existing_slot, Some(prop.slot))?;
        let existing_mdec = existing_slot.as_membership().ok_or_else(|| {
            anyhow!(
                "CRITICAL: Slot {} already committed as a Lease decision, cannot commit Membership transition",
                prop.slot
            )
        })?;
        if existing_mdec.canonical_digest()? != decision.canonical_digest()? {
            anyhow::bail!(
                "CRITICAL: Conflicting durable membership transition already committed for ({}, epoch={}, slot={})",
                prop.group_id,
                prop.prev_epoch,
                prop.slot
            );
        }

        // Record 2: `sys_mesh_membership_history:$hkey`
        let mut hresp = db
            .client
            .query("SELECT * FROM type::record('sys_mesh_membership_history', $hkey)")
            .bind(("hkey", hkey))
            .await?;
        let hrows: Vec<serde_json::Value> = hresp.take(0).unwrap_or_default();
        let raw_h = hrows
            .first()
            .ok_or_else(|| anyhow!("Membership history conflict reported for epoch {} but record missing", prop.next_epoch))?;
        let existing_h: DurableMembershipEpochRecord = serde_json::from_value(raw_h.clone())
            .map_err(|e| anyhow!("Malformed existing membership history record: {}", e))?;
        if existing_h.group_id != prop.group_id
            || existing_h.membership_epoch != prop.next_epoch
            || existing_h.mode != prop.mode
        {
            anyhow::bail!(
                "CRITICAL: Existing membership history record for epoch {} disagrees with proposed group/epoch/mode",
                prop.next_epoch
            );
        }
        let mut existing_h_sorted = existing_h.members.clone();
        existing_h_sorted.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        if existing_h_sorted != sorted_members {
            anyhow::bail!(
                "CRITICAL: Existing membership history members for epoch {} disagree with proposed members",
                prop.next_epoch
            );
        }
        let existing_htrans = existing_h
            .transition
            .as_ref()
            .ok_or_else(|| anyhow!("Existing epoch {} history record lacks transition certificate", prop.next_epoch))?;
        self.validate_durable_membership_decision(existing_htrans, Some(prop.slot))?;
        if existing_htrans.canonical_digest()? != decision.canonical_digest()? {
            anyhow::bail!(
                "CRITICAL: Conflicting membership history already committed for epoch {}",
                prop.next_epoch
            );
        }

        // Record 3: `sys_mesh_membership:$gkey` — verify active tip matches `prop.next_epoch` OR
        // is a cryptographically verified successor epoch in `sys_mesh_membership_history`!
        let mut mresp = db
            .client
            .query("SELECT * FROM type::record('sys_mesh_membership', $gkey)")
            .bind(("gkey", gkey))
            .await?;
        let mrows: Vec<serde_json::Value> = mresp.take(0).unwrap_or_default();
        let raw_m = mrows
            .first()
            .ok_or_else(|| anyhow!("Active sys_mesh_membership record missing during idempotent retry check"))?;
        let active_m: DurableMembershipRecord = serde_json::from_value(raw_m.clone())
            .map_err(|e| anyhow!("Malformed active sys_mesh_membership record: {}", e))?;
        if active_m.group_id != prop.group_id
            || active_m.membership_epoch < prop.next_epoch
            || active_m.next_slot < prop.slot.saturating_add(1)
        {
            anyhow::bail!(
                "CRITICAL: Active sys_mesh_membership (epoch={}, next_slot={}) is inconsistent with committed transition to epoch {} at slot {}",
                active_m.membership_epoch,
                active_m.next_slot,
                prop.next_epoch,
                prop.slot
            );
        }
        let mut active_m_sorted = active_m.members.clone();
        active_m_sorted.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        if active_m.membership_epoch == prop.next_epoch {
            if active_m.mode != prop.mode || active_m_sorted != sorted_members {
                anyhow::bail!(
                    "CRITICAL: Active sys_mesh_membership record disagrees with committed epoch {} configuration",
                    prop.next_epoch
                );
            }
        } else {
            // Walk & verify successor chain `(prop.next_epoch + 1)..=active_m.membership_epoch`!
            let mut cur_cfg = MembershipEpochConfig {
                mode: prop.mode,
                members: sorted_members
                    .iter()
                    .cloned()
                    .map(|m| (m.node_id.clone(), m))
                    .collect(),
            };
            let mut min_slot = prop.slot.saturating_add(1);
            for ep in (prop.next_epoch + 1)..=active_m.membership_epoch {
                let succ_hkey = membership_epoch_key(&prop.group_id, ep);
                let mut sh_resp = db
                    .client
                    .query("SELECT * FROM type::record('sys_mesh_membership_history', $hkey)")
                    .bind(("hkey", succ_hkey))
                    .await?;
                let sh_rows: Vec<serde_json::Value> = sh_resp.take(0).unwrap_or_default();
                let raw_sh = sh_rows.first().ok_or_else(|| {
                    anyhow!(
                        "CRITICAL: Missing verified successor epoch {} between epoch {} and active epoch {}",
                        ep,
                        prop.next_epoch,
                        active_m.membership_epoch
                    )
                })?;
                let succ_rec: DurableMembershipEpochRecord = serde_json::from_value(raw_sh.clone())
                    .map_err(|e| anyhow!("Malformed successor epoch {} history record: {}", ep, e))?;
                let succ_dec = succ_rec.transition.as_ref().ok_or_else(|| {
                    anyhow!("Unproven successor epoch {} missing transition certificate", ep)
                })?;
                self.validate_membership_transition_against_prev(succ_dec, &cur_cfg, ep - 1, None)?;
                let mut succ_sorted = succ_rec.members.clone();
                succ_sorted.sort_by(|a, b| a.node_id.cmp(&b.node_id));
                let mut succ_prop_sorted = succ_dec.proposal.new_members.clone();
                succ_prop_sorted.sort_by(|a, b| a.node_id.cmp(&b.node_id));
                if succ_rec.group_id != prop.group_id
                    || succ_rec.membership_epoch != ep
                    || succ_rec.mode != succ_dec.proposal.mode
                    || succ_sorted != succ_prop_sorted
                {
                    anyhow::bail!(
                        "CRITICAL: Successor epoch {} history record disagrees with its transition certificate",
                        ep
                    );
                }
                min_slot = min_slot.max(succ_dec.proposal.slot.saturating_add(1));
                cur_cfg = MembershipEpochConfig {
                    mode: succ_rec.mode,
                    members: succ_sorted
                        .into_iter()
                        .map(|m| (m.node_id.clone(), m))
                        .collect(),
                };
            }
            let mut tip_sorted: Vec<GroupMember> = cur_cfg.members.values().cloned().collect();
            tip_sorted.sort_by(|a, b| a.node_id.cmp(&b.node_id));
            if active_m.mode != cur_cfg.mode
                || active_m_sorted != tip_sorted
                || active_m.next_slot < min_slot
            {
                anyhow::bail!(
                    "CRITICAL: Active sys_mesh_membership (epoch={}) disagrees with verified successor chain tip",
                    active_m.membership_epoch
                );
            }
        }
        Ok(())
    }

    /// Unified atomic lease slot-commit arbitration shared by BOTH `commit_exclusive_lease` AND
    /// `recover_and_commit_slot`!
    async fn persist_slot_decision_atomic(&self, lease: &FencedLease, new_next_slot: u64) -> Result<()> {
        let Some(ref db) = self.db else { return Ok(()) };
        let skey = slot_decision_key(&lease.group_id, lease.qc.epoch, lease.qc.slot);
        let gkey = blake3::hash(self.group_id.as_bytes()).to_hex().to_string();
        let slot_dec = DurableSlotDecision::Lease(lease.clone());
        let lease_val = serde_json::to_value(&slot_dec)?;
        let mem_rec = DurableMembershipRecord {
            group_id: self.group_id.clone(),
            mode: self.mode,
            membership_epoch: self.membership_epoch,
            current_term: self.current_term.max(lease.qc.term),
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

        // Slot record already exists in `sys_mesh_decision_log`: validate it AND verify exact digest match!
        let mut resp = db
            .client
            .query("SELECT * FROM type::record('sys_mesh_decision_log', $skey)")
            .bind(("skey", skey))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let raw_existing = rows
            .first()
            .ok_or_else(|| anyhow!("Slot decision reported existing but could not be read back"))?;
        let existing = parse_durable_slot_decision(raw_existing.clone())?;
        self.validate_durable_slot_decision(&existing, Some(lease.qc.slot))?;
        let existing_lease = existing.as_lease().ok_or_else(|| {
            anyhow!(
                "CRITICAL: Slot {} already committed as Membership transition, cannot commit Lease",
                lease.qc.slot
            )
        })?;
        if existing_lease.canonical_digest() != lease.canonical_digest() {
            anyhow::bail!(
                "CRITICAL: Conflicting durable decision already committed for ({}, epoch={}, slot={})",
                lease.group_id,
                lease.qc.epoch,
                lease.qc.slot
            );
        }
        Ok(())
    }

    /// Read ALL durable slot decisions in `sys_mesh_decision_log` matching `(self.group_id, self.membership_epoch, slot)`.
    /// Explicitly fails closed on malformed records rather than silently discarding them!
    async fn read_durable_slot_decisions(&self, slot: u64) -> Result<Vec<DurableSlotDecision>> {
        let Some(ref db) = self.db else {
            return Ok(self
                .active_leases
                .values()
                .filter(|l| l.qc.slot == slot && l.qc.epoch == self.membership_epoch)
                .cloned()
                .map(DurableSlotDecision::Lease)
                .collect());
        };
        let mut resp = db.client.query("SELECT * FROM sys_mesh_decision_log").await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let mut out = Vec::new();
        for v in rows {
            if let Some(row_gid) = decision_row_group_id(&v) {
                if row_gid != self.group_id {
                    continue;
                }
            }
            let dec = parse_durable_slot_decision(v).map_err(|e| {
                anyhow!(
                    "Malformed durable decision record in sys_mesh_decision_log for '{}': {}",
                    self.group_id,
                    e
                )
            })?;
            if dec.group_id() == self.group_id
                && dec.qc().epoch == self.membership_epoch
                && dec.qc().slot == slot
            {
                out.push(dec);
            }
        }
        Ok(out)
    }

    /// Atomic persistence for a protocol-defined `NoOpDecision` (filling an unaccepted gap slot).
    async fn persist_noop_decision_atomic(
        &self,
        decision: &NoOpDecision,
        new_next_slot: u64,
    ) -> Result<()> {
        let Some(ref db) = self.db else { return Ok(()) };
        let skey = slot_decision_key(&decision.proposal.group_id, decision.qc.epoch, decision.qc.slot);
        let gkey = blake3::hash(self.group_id.as_bytes()).to_hex().to_string();
        let slot_dec = DurableSlotDecision::NoOp(decision.clone());
        let dec_val = serde_json::to_value(&slot_dec)?;
        let mem_rec = DurableMembershipRecord {
            group_id: self.group_id.clone(),
            mode: self.mode,
            membership_epoch: self.membership_epoch,
            current_term: self.current_term.max(decision.qc.term),
            next_slot: new_next_slot,
            members: self.members.values().cloned().collect(),
        };
        let mem_val = serde_json::to_value(&mem_rec)?;

        let tx_res = db
            .client
            .query(
                "BEGIN TRANSACTION;\
                 CREATE type::record('sys_mesh_decision_log', $skey) CONTENT $d;\
                 UPSERT type::record('sys_mesh_membership', $gkey) CONTENT $m;\
                 COMMIT TRANSACTION;",
            )
            .bind(("skey", skey.clone()))
            .bind(("d", dec_val))
            .bind(("gkey", gkey))
            .bind(("m", mem_val))
            .await;

        match tx_res {
            Ok(resp) => match resp.check() {
                Ok(_) => return Ok(()),
                Err(e) if is_already_exists_error(&e) => {}
                Err(e) => return Err(anyhow!("Failed atomic NoOp commit transaction: {}", e)),
            },
            Err(e) if is_already_exists_error(&e) => {}
            Err(e) => return Err(anyhow!("Database error in atomic NoOp commit: {}", e)),
        }

        let mut resp = db
            .client
            .query("SELECT * FROM type::record('sys_mesh_decision_log', $skey)")
            .bind(("skey", skey))
            .await?;
        let rows: Vec<serde_json::Value> = resp.take(0).unwrap_or_default();
        let raw_existing = rows
            .first()
            .ok_or_else(|| anyhow!("NoOp slot decision conflict reported but record missing"))?;
        let existing = parse_durable_slot_decision(raw_existing.clone())?;
        self.validate_durable_slot_decision(&existing, Some(decision.qc.slot))?;
        let existing_noop = existing.as_noop().ok_or_else(|| {
            anyhow!(
                "CRITICAL: Slot {} already committed as non-NoOp decision",
                decision.qc.slot
            )
        })?;
        if existing_noop.canonical_digest() != decision.canonical_digest() {
            anyhow::bail!(
                "CRITICAL: Conflicting durable NoOp decision at slot {}",
                decision.qc.slot
            );
        }
        Ok(())
    }

    /// Validate any `DurableSlotDecision` (`Lease`, `Membership`, or `NoOp`).
    pub fn validate_durable_slot_decision(
        &self,
        decision: &DurableSlotDecision,
        expected_slot: Option<u64>,
    ) -> Result<()> {
        match decision {
            DurableSlotDecision::Lease(l) => self.validate_durable_decision(l, expected_slot),
            DurableSlotDecision::Membership(m) => {
                self.validate_durable_membership_decision(m, expected_slot)
            }
            DurableSlotDecision::NoOp(n) => self.validate_durable_noop_decision(n, expected_slot),
        }
    }

    pub fn validate_durable_noop_decision(
        &self,
        decision: &NoOpDecision,
        expected_slot: Option<u64>,
    ) -> Result<()> {
        let prop = &decision.proposal;
        if prop.group_id != self.group_id {
            anyhow::bail!("NoOp decision group_id '{}' does not match '{}'", prop.group_id, self.group_id);
        }
        if let Some(slot) = expected_slot {
            if prop.slot != slot || decision.qc.slot != slot {
                anyhow::bail!("NoOp decision slot mismatch");
            }
        }
        if decision.qc.slot != prop.slot || decision.qc.epoch != prop.epoch {
            anyhow::bail!("NoOp decision QC (epoch/slot) disagrees with proposal");
        }
        let epoch_cfg = self.membership_history.get(&prop.epoch).ok_or_else(|| {
            anyhow!("No durable membership config for epoch {} to validate NoOp", prop.epoch)
        })?;
        self.verify_qc_for_epoch(&decision.qc, epoch_cfg, prop.epoch)?;
        let expected_digest = prop.canonical_digest();
        if decision.qc.proposal_hash != expected_digest {
            anyhow::bail!("NoOp decision QC proposal_hash disagrees with canonical digest");
        }
        Ok(())
    }

    pub fn validate_durable_membership_decision(
        &self,
        decision: &MembershipTransitionDecision,
        expected_slot: Option<u64>,
    ) -> Result<()> {
        let prev_epoch = decision.proposal.prev_epoch;
        let prev_cfg = self.membership_history.get(&prev_epoch).ok_or_else(|| {
            anyhow!(
                "No durable membership configuration available for ({}, epoch={}) to validate membership transition to epoch {}",
                self.group_id,
                prev_epoch,
                decision.proposal.next_epoch
            )
        })?;
        self.validate_membership_transition_against_prev(decision, prev_cfg, prev_epoch, expected_slot)
    }

    fn validate_membership_transition_against_prev(
        &self,
        decision: &MembershipTransitionDecision,
        prev_cfg: &MembershipEpochConfig,
        expected_prev_epoch: u64,
        expected_slot: Option<u64>,
    ) -> Result<()> {
        let prop = &decision.proposal;
        if prop.group_id != self.group_id {
            anyhow::bail!(
                "Membership transition group_id '{}' does not match '{}'",
                prop.group_id,
                self.group_id
            );
        }
        if prop.prev_epoch != expected_prev_epoch || prop.next_epoch != expected_prev_epoch + 1 {
            anyhow::bail!(
                "Membership transition epoch ({} -> {}) does not match expected predecessor {}",
                prop.prev_epoch,
                prop.next_epoch,
                expected_prev_epoch
            );
        }
        if prop.mode != prev_cfg.mode {
            anyhow::bail!(
                "Membership transition mode {:?} does not match predecessor mode {:?}",
                prop.mode,
                prev_cfg.mode
            );
        }
        if let Some(slot) = expected_slot {
            if prop.slot != slot {
                anyhow::bail!(
                    "Membership transition slot {} does not match expected slot {}",
                    prop.slot,
                    slot
                );
            }
        }
        if decision.qc.slot != prop.slot {
            anyhow::bail!(
                "Membership transition QC slot {} disagrees with proposal slot {}",
                decision.qc.slot,
                prop.slot
            );
        }
        let expected_digest = prop.canonical_digest()?;
        self.verify_qc_for_epoch(&decision.qc, prev_cfg, expected_prev_epoch)?;
        if decision.qc.proposal_hash != expected_digest {
            anyhow::bail!(
                "Membership transition QC proposal_hash '{}' does not match canonical digest '{}'",
                decision.qc.proposal_hash,
                expected_digest
            );
        }
        Ok(())
    }

    /// Shared durable decision validator used by `open_durable()`, `recover_and_commit_slot()`,
    /// and `persist_slot_decision_atomic()`.
    ///
    /// Verifies group, fencing epoch, validity bounds, slot agreement, durable membership epoch
    /// configuration (supporting historical membership epochs), authorized holder, Ed25519 quorum
    /// signatures, and canonical `NEXUS-LEASE-PROPOSAL-v2` digest binding.
    pub fn validate_durable_decision(
        &self,
        lease: &FencedLease,
        expected_slot: Option<u64>,
    ) -> Result<()> {
        if lease.group_id != self.group_id {
            anyhow::bail!(
                "Durable decision group_id '{}' does not match '{}'",
                lease.group_id,
                self.group_id
            );
        }
        if lease.fencing_epoch == 0 {
            anyhow::bail!("Durable decision '{}' has invalid fencing_epoch 0", lease.lease_id);
        }
        if lease.expires_at_ms <= lease.issued_at_ms {
            anyhow::bail!("Durable decision '{}' has invalid validity interval", lease.lease_id);
        }
        if lease.expires_at_ms - lease.issued_at_ms > self.max_lease_ttl_ms {
            anyhow::bail!(
                "Durable decision '{}' duration exceeds group max_lease_ttl_ms",
                lease.lease_id
            );
        }
        if let Some(slot) = expected_slot {
            if lease.qc.slot != slot {
                anyhow::bail!(
                    "Durable decision QC slot {} does not match expected slot {}",
                    lease.qc.slot,
                    slot
                );
            }
        }
        let epoch_cfg = self.membership_history.get(&lease.qc.epoch).ok_or_else(|| {
            anyhow!(
                "No durable membership configuration available for ({}, epoch={}) to validate decision '{}'",
                self.group_id,
                lease.qc.epoch,
                lease.lease_id
            )
        })?;
        if !epoch_cfg.members.contains_key(&lease.holder_node_id) {
            anyhow::bail!(
                "Durable decision holder '{}' was not an authorized member in epoch {}",
                lease.holder_node_id,
                lease.qc.epoch
            );
        }
        self.verify_qc_for_epoch(&lease.qc, epoch_cfg, lease.qc.epoch)?;
        let expected_digest = lease.canonical_digest();
        if lease.qc.proposal_hash != expected_digest {
            anyhow::bail!(
                "Durable decision '{}' QC proposal_hash '{}' does not match canonical lease digest '{}'",
                lease.lease_id,
                lease.qc.proposal_hash,
                expected_digest
            );
        }
        Ok(())
    }

    pub fn quorum_size(&self) -> usize {
        self.mode.quorum_size(self.members.len())
    }

    /// Type-aware autonomous standby coordinator recovery & commit for `slot` (supports BOTH
    /// `SlotProposal::Lease` and `SlotProposal::Membership` transitions):
    /// 1. Reads & validates durable `sys_mesh_decision_log` for `slot` (failing closed on conflicts/corruption).
    /// 2. Validates every `(SignedVote, Option<SlotProposal>)` from voters' durable locks.
    /// 3. Reconstructs the unique verified `QuorumCertificate` (failing closed on conflicting quorums).
    /// 4. Requires a matching canonical `SlotProposal` (fails closed on legacy locks missing payload).
    /// 5. Persists atomically (`persist_slot_decision_atomic` or `persist_membership_transition_atomic`)
    ///    and updates in-memory state ONLY after durable persistence succeeds!
    pub async fn recover_and_commit_slot(
        &mut self,
        slot: u64,
        locked_entries: Vec<(SignedVote, Option<SlotProposal>)>,
    ) -> Result<Option<DurableSlotDecision>> {
        // 1. Reconcile & cryptographically validate complete durable decision log for this slot
        let durable_decisions = self.read_durable_slot_decisions(slot).await?;
        let mut distinct_durable_digests = HashSet::new();
        for d in &durable_decisions {
            self.validate_durable_slot_decision(d, Some(slot))?;
            distinct_durable_digests.insert(d.canonical_digest()?);
        }
        if distinct_durable_digests.len() > 1 {
            anyhow::bail!(
                "CRITICAL: Conflicting durable decisions exist in sys_mesh_decision_log for slot {}!",
                slot
            );
        }
        let existing_durable = durable_decisions.into_iter().next();

        // 2. Validate voter locks & canonical SlotProposal payloads.
        //    STRICT RULE: EVERY matching voter lock MUST carry a complete `Some(SlotProposal)`
        //    whose canonical digest & contents match. Incomplete (`None`) locks fail closed
        //    immediately rather than being silently skipped or mixed into a quorum!
        let mut votes_by_hash: HashMap<String, Vec<SignedVote>> = HashMap::new();
        let mut proposals_by_hash: HashMap<String, SlotProposal> = HashMap::new();
        for (v, prop_opt) in locked_entries {
            if v.group_id != self.group_id || v.epoch != self.membership_epoch || v.slot != slot {
                anyhow::bail!(
                    "Unexpected voter lock identity in slot {} recovery: expected ({}, epoch={}, slot={}), got ({}, epoch={}, slot={}) from '{}'",
                    slot,
                    self.group_id,
                    self.membership_epoch,
                    slot,
                    v.group_id,
                    v.epoch,
                    v.slot,
                    v.voter_node_id
                );
            }
            let Some(ref p) = prop_opt else {
                anyhow::bail!(
                    "Incomplete durable voter lock from '{}' for ({}, epoch={}, slot={}): missing canonical SlotProposal payload",
                    v.voter_node_id,
                    self.group_id,
                    self.membership_epoch,
                    slot
                );
            };
            let computed = p.validate_for_vote(&self.group_id, self.membership_epoch, slot)?;
            if computed != v.proposal_hash {
                anyhow::bail!(
                    "Malformed or tampered SlotProposal from voter '{}' for slot {}: digest mismatch",
                    v.voter_node_id,
                    slot
                );
            }
            if let Some(prev_p) = proposals_by_hash.get(&v.proposal_hash) {
                if prev_p != p {
                    anyhow::bail!(
                        "Conflicting proposal payloads for hash '{}' in slot {}",
                        v.proposal_hash,
                        slot
                    );
                }
            } else {
                proposals_by_hash.insert(v.proposal_hash.clone(), p.clone());
            }
            votes_by_hash.entry(v.proposal_hash.clone()).or_default().push(v);
        }

        // 3. Establish unique valid QC (preserving the term carried by the votes)
        let mut valid_qcs = Vec::new();
        for (proposal_hash, votes) in votes_by_hash {
            let mut votes_by_term: HashMap<u64, Vec<SignedVote>> = HashMap::new();
            for v in votes {
                votes_by_term.entry(v.term).or_default().push(v);
            }
            for (vote_term, term_votes) in votes_by_term {
                let qc = QuorumCertificate {
                    group_id: self.group_id.clone(),
                    epoch: self.membership_epoch,
                    term: vote_term,
                    slot,
                    proposal_hash: proposal_hash.clone(),
                    mode: self.mode,
                    votes: term_votes,
                };
                if self.verify_qc(&qc).is_ok() {
                    valid_qcs.push(qc);
                }
            }
        }
        if valid_qcs.len() > 1 {
            let distinct_hashes: HashSet<&str> =
                valid_qcs.iter().map(|q| q.proposal_hash.as_str()).collect();
            if distinct_hashes.len() > 1 {
                anyhow::bail!(
                    "CRITICAL: Conflicting quorum certificates detected during slot {} recovery!",
                    slot
                );
            }
            valid_qcs.sort_by_key(|q| std::cmp::Reverse(q.term));
            valid_qcs.truncate(1);
        }

        if let Some(committed) = existing_durable {
            if let Some(ref recovered_qc) = valid_qcs.first() {
                if recovered_qc.proposal_hash != committed.canonical_digest()? {
                    anyhow::bail!(
                        "CRITICAL: Recovered voter quorum conflicts with durable committed decision for slot {}!",
                        slot
                    );
                }
            }
            match &committed {
                DurableSlotDecision::Lease(lease) => {
                    if slot >= self.next_slot {
                        self.next_slot = slot + 1;
                    }
                    let cur_max = self.max_fencing_epoch.get(&lease.resource_key).copied().unwrap_or(0);
                    if lease.fencing_epoch > cur_max {
                        self.max_fencing_epoch.insert(lease.resource_key.clone(), lease.fencing_epoch);
                        self.active_leases.insert(lease.resource_key.clone(), lease.clone());
                    }
                }
                DurableSlotDecision::Membership(mdec) => {
                    if mdec.proposal.next_epoch > self.membership_epoch {
                        let new_map: HashMap<String, GroupMember> = mdec
                            .proposal
                            .new_members
                            .iter()
                            .cloned()
                            .map(|m| (m.node_id.clone(), m))
                            .collect();
                        self.membership_epoch = mdec.proposal.next_epoch;
                        self.next_slot = self.next_slot.max(slot + 1);
                        self.membership_history.insert(
                            mdec.proposal.next_epoch,
                            MembershipEpochConfig {
                                mode: mdec.proposal.mode,
                                members: new_map.clone(),
                            },
                        );
                        self.members = new_map;
                    }
                }
                DurableSlotDecision::NoOp(_) => {
                    if slot >= self.next_slot {
                        self.next_slot = slot + 1;
                    }
                }
            }
            self.current_term = self.current_term.max(committed.qc().term);
            return Ok(Some(committed));
        }

        let Some(qc) = valid_qcs.into_iter().next() else {
            return Ok(None);
        };

        // 4. Require canonical SlotProposal (fail closed for legacy locks missing proposal payload!)
        let proposal = proposals_by_hash.remove(&qc.proposal_hash).ok_or_else(|| {
            anyhow!(
                "Cannot autonomously recover slot {}: durable voter locks lack canonical SlotProposal payload",
                slot
            )
        })?;

        match proposal {
            SlotProposal::Lease(prop) => {
                if prop.group_id != self.group_id {
                    anyhow::bail!("Recovered lease proposal group_id '{}' mismatch", prop.group_id);
                }
                if prop.expires_at_ms <= prop.issued_at_ms
                    || prop.expires_at_ms - prop.issued_at_ms > self.max_lease_ttl_ms
                {
                    anyhow::bail!("Recovered lease proposal violates group validity/TTL bounds");
                }
                let lease = FencedLease {
                    lease_id: prop.lease_id,
                    group_id: prop.group_id,
                    resource_key: prop.resource_key,
                    holder_node_id: prop.holder_node_id,
                    workload_id: prop.workload_id,
                    fencing_epoch: prop.fencing_epoch,
                    issued_at_ms: prop.issued_at_ms,
                    expires_at_ms: prop.expires_at_ms,
                    qc,
                };
                self.validate_durable_decision(&lease, Some(slot))?;
                let new_next_slot = self.next_slot.max(slot + 1);
                self.persist_slot_decision_atomic(&lease, new_next_slot).await?;

                self.current_term = self.current_term.max(lease.qc.term);
                self.next_slot = new_next_slot;
                let cur_max = self.max_fencing_epoch.get(&lease.resource_key).copied().unwrap_or(0);
                if lease.fencing_epoch > cur_max {
                    self.max_fencing_epoch.insert(lease.resource_key.clone(), lease.fencing_epoch);
                    self.active_leases.insert(lease.resource_key.clone(), lease.clone());
                }
                Ok(Some(DurableSlotDecision::Lease(lease)))
            }
            SlotProposal::Membership(prop) => {
                let dec = MembershipTransitionDecision { proposal: prop, qc };
                self.validate_durable_membership_decision(&dec, Some(slot))?;
                let new_next_slot = self.next_slot.max(slot + 1);
                self.persist_membership_transition_atomic(&dec, new_next_slot).await?;

                let new_map: HashMap<String, GroupMember> = dec
                    .proposal
                    .new_members
                    .iter()
                    .cloned()
                    .map(|m| (m.node_id.clone(), m))
                    .collect();
                self.current_term = self.current_term.max(dec.qc.term);
                self.membership_epoch = dec.proposal.next_epoch;
                self.next_slot = new_next_slot;
                self.membership_history.insert(
                    dec.proposal.next_epoch,
                    MembershipEpochConfig {
                        mode: dec.proposal.mode,
                        members: new_map.clone(),
                    },
                );
                self.members = new_map;
                Ok(Some(DurableSlotDecision::Membership(dec)))
            }
            SlotProposal::NoOp(prop) => {
                let dec = NoOpDecision { proposal: prop, qc };
                self.validate_durable_noop_decision(&dec, Some(slot))?;
                let new_next_slot = self.next_slot.max(slot + 1);
                self.persist_noop_decision_atomic(&dec, new_next_slot).await?;

                self.current_term = self.current_term.max(dec.qc.term);
                self.next_slot = new_next_slot;
                Ok(Some(DurableSlotDecision::NoOp(dec)))
            }
        }
    }

    /// Phase-1 takeover planner: verifies a quorum of `TermPromise`s (`TermCertificate`), checks
    /// Paxos value adoption across EVERY slot from `from_slot ..= max_reported_slot`, fails closed
    /// on conflicting equal-highest-`accepted_term` proposals, and emits a contiguous recovery plan
    /// (adopting accepted proposals and filling unaccepted gaps with `NoOpProposal`).
    pub fn plan_takeover_from_promises(
        &self,
        leader_id: &str,
        term: u64,
        from_slot: u64,
        promises: Vec<TermPromise>,
    ) -> Result<(TermCertificate, Vec<(u64, SlotRecoveryAction)>)> {
        let cert = TermCertificate {
            group_id: self.group_id.clone(),
            epoch: self.membership_epoch,
            term,
            leader_id: leader_id.to_string(),
            from_slot,
            mode: self.mode,
            promises,
        };
        let current_cfg = MembershipEpochConfig {
            mode: self.mode,
            members: self.members.clone(),
        };
        // Always verify certificate quorum & signatures (even when no accepted locks exist!)
        let _ = verify_term_certificate_and_adoption(&cert, &current_cfg, from_slot)?;

        let max_slot = cert
            .promises
            .iter()
            .flat_map(|p| p.accepted_locks.iter())
            .filter(|l| l.epoch == self.membership_epoch && l.slot >= from_slot)
            .map(|l| l.slot)
            .max();

        let mut plan = Vec::new();
        if let Some(max_s) = max_slot {
            for s in from_slot..=max_s {
                match verify_term_certificate_and_adoption(&cert, &current_cfg, s)? {
                    Some(adopted) => plan.push((s, SlotRecoveryAction::Adopt(adopted))),
                    None => plan.push((
                        s,
                        SlotRecoveryAction::FillGapNoOp(NoOpProposal {
                            group_id: self.group_id.clone(),
                            epoch: self.membership_epoch,
                            slot: s,
                            reason: format!("takeover_term_{}_gap_fill", term),
                        }),
                    )),
                }
            }
        }
        Ok((cert, plan))
    }

    /// Commit a quorum-certified `NoOpProposal` to close an unaccepted gap slot contiguously.
    pub async fn commit_noop_with_quorum(
        &mut self,
        proposal: &NoOpProposal,
        votes: Vec<SignedVote>,
    ) -> Result<NoOpDecision> {
        if proposal.group_id != self.group_id
            || proposal.epoch != self.membership_epoch
            || proposal.slot != self.next_slot
        {
            anyhow::bail!("NoOp proposal (group/epoch/slot) does not match group state");
        }
        let expected_hash = proposal.canonical_digest();
        let vote_term = votes
            .iter()
            .filter(|v| {
                v.group_id == self.group_id
                    && v.epoch == self.membership_epoch
                    && v.slot == proposal.slot
                    && v.proposal_hash == expected_hash
            })
            .map(|v| v.term)
            .max()
            .unwrap_or(self.current_term);
        let mut valid_votes = Vec::new();
        let mut unique = HashSet::new();
        for v in votes {
            if v.group_id == self.group_id
                && v.epoch == self.membership_epoch
                && v.term == vote_term
                && v.slot == proposal.slot
                && v.proposal_hash == expected_hash
                && unique.insert(v.voter_node_id.clone())
            {
                valid_votes.push(v);
            }
        }
        let qc = QuorumCertificate {
            group_id: self.group_id.clone(),
            epoch: self.membership_epoch,
            term: vote_term,
            slot: proposal.slot,
            proposal_hash: expected_hash,
            mode: self.mode,
            votes: valid_votes,
        };
        let decision = NoOpDecision {
            proposal: proposal.clone(),
            qc,
        };
        self.validate_durable_noop_decision(&decision, Some(proposal.slot))?;
        let new_next_slot = self.next_slot + 1;
        self.persist_noop_decision_atomic(&decision, new_next_slot)
            .await?;
        self.current_term = self.current_term.max(vote_term);
        self.next_slot = new_next_slot;
        Ok(decision)
    }

    /// Autonomous multi-slot coordinator takeover & contiguous catch-up against `voters`:
    /// 1. Phase-1 `prepare_term` fan-out across `voters` -> verified `TermCertificate`.
    /// 2. Builds contiguous recovery plan (`self.next_slot ..= max_reported_slot`), adopting
    ///    highest-`accepted_term` proposals and filling unaccepted gaps with `NoOpProposal`.
    /// 3. Drives every slot through Phase-2 `cast_vote` (carrying `TermCertificate`!) and atomic
    ///    durable commit, installing any recovered `MembershipTransitionDecision` onto `voters`.
    /// 4. Returns `TakeoverReport` only after the entire contiguous prefix is durably committed!
    pub async fn execute_takeover_catch_up(
        &mut self,
        leader_id: &str,
        new_term: u64,
        voters: &[VoterNode],
    ) -> Result<TakeoverReport> {
        if new_term <= self.current_term {
            anyhow::bail!(
                "Takeover term {} must exceed current_term {}",
                new_term,
                self.current_term
            );
        }
        let from_slot = self.next_slot;
        let prep_req = PrepareTermRequest {
            group_id: self.group_id.clone(),
            epoch: self.membership_epoch,
            term: new_term,
            leader_id: leader_id.to_string(),
            from_slot,
        };

        let mut join_set = tokio::task::JoinSet::new();
        for v in voters {
            if self.members.contains_key(&v.node_id) {
                let vc = v.clone();
                let rc = prep_req.clone();
                join_set.spawn(async move { vc.prepare_term(&rc).await });
            }
        }
        let mut promises = Vec::new();
        while let Some(res) = join_set.join_next().await {
            if let Ok(Ok(p)) = res {
                promises.push(p);
            }
        }

        let (cert, plan) = self.plan_takeover_from_promises(leader_id, new_term, from_slot, promises)?;
        self.current_term = new_term;
        self.active_term_cert = Some(cert.clone());

        let mut recovered_slots = Vec::new();
        let mut filled_gaps = Vec::new();
        let mut pending_removed_fence_nodes = Vec::new();

        for (slot, action) in plan {
            // Check if already durably committed in local decision log first
            let existing = self.read_durable_slot_decisions(slot).await?;
            if !existing.is_empty() {
                let _ = self.recover_and_commit_slot(slot, vec![]).await?;
                recovered_slots.push(slot);
                continue;
            }

            let vreq = match &action {
                SlotRecoveryAction::Adopt(SlotProposal::Lease(lp)) => {
                    VoteRequest::for_lease(self.membership_epoch, slot, lp.clone())
                        .with_term(new_term, leader_id, cert.clone())
                }
                SlotRecoveryAction::Adopt(SlotProposal::Membership(mp)) => {
                    VoteRequest::for_membership(mp.clone())?
                        .with_term(new_term, leader_id, cert.clone())
                }
                SlotRecoveryAction::Adopt(SlotProposal::NoOp(np))
                | SlotRecoveryAction::FillGapNoOp(np) => {
                    VoteRequest::for_noop(np.clone()).with_term(new_term, leader_id, cert.clone())
                }
            };

            let mut vset = tokio::task::JoinSet::new();
            for v in voters {
                if self.members.contains_key(&v.node_id) {
                    let vc = v.clone();
                    let rc = vreq.clone();
                    vset.spawn(async move { vc.cast_vote(&rc).await });
                }
            }
            let mut votes = Vec::new();
            while let Some(res) = vset.join_next().await {
                if let Ok(Ok(sv)) = res {
                    votes.push(sv);
                }
            }

            let prev_cfg = MembershipEpochConfig {
                mode: self.mode,
                members: self.members.clone(),
            };
            match action {
                SlotRecoveryAction::Adopt(SlotProposal::Lease(lp)) => {
                    let qc = QuorumCertificate {
                        group_id: self.group_id.clone(),
                        epoch: self.membership_epoch,
                        term: new_term,
                        slot,
                        proposal_hash: lp.canonical_digest(),
                        mode: self.mode,
                        votes,
                    };
                    self.verify_qc(&qc)?;
                    let lease = FencedLease {
                        lease_id: lp.lease_id,
                        group_id: lp.group_id,
                        resource_key: lp.resource_key,
                        holder_node_id: lp.holder_node_id,
                        workload_id: lp.workload_id,
                        fencing_epoch: lp.fencing_epoch,
                        issued_at_ms: lp.issued_at_ms,
                        expires_at_ms: lp.expires_at_ms,
                        qc,
                    };
                    self.validate_durable_decision(&lease, Some(slot))?;
                    let new_next = self.next_slot.max(slot + 1);
                    self.persist_slot_decision_atomic(&lease, new_next).await?;
                    self.next_slot = new_next;
                    let cur_max = self.max_fencing_epoch.get(&lease.resource_key).copied().unwrap_or(0);
                    if lease.fencing_epoch > cur_max {
                        self.max_fencing_epoch.insert(lease.resource_key.clone(), lease.fencing_epoch);
                        self.active_leases.insert(lease.resource_key.clone(), lease);
                    }
                    recovered_slots.push(slot);
                }
                SlotRecoveryAction::Adopt(SlotProposal::Membership(mp)) => {
                    let mdec = self.reconfigure_membership_with_quorum(&mp, votes).await?;
                    // Dual-quorum activation safety rule:
                    // 1. Old-configuration fence quorum MUST durably advance `min_active_epoch >= next_epoch`
                    //    so NO disconnected subset of `prev_cfg` can ever commit a conflicting old-epoch decision!
                    // 2. New-configuration activation quorum MUST durably install & verify `next_epoch`!
                    let pending = self
                        .activate_membership_transition(&mdec, &prev_cfg, voters)
                        .await?;
                    pending_removed_fence_nodes.extend(pending);
                    recovered_slots.push(slot);
                }
                SlotRecoveryAction::Adopt(SlotProposal::NoOp(np)) => {
                    let _ = self.commit_noop_with_quorum(&np, votes).await?;
                    recovered_slots.push(slot);
                }
                SlotRecoveryAction::FillGapNoOp(np) => {
                    let _ = self.commit_noop_with_quorum(&np, votes).await?;
                    filled_gaps.push(slot);
                }
            }
        }

        Ok(TakeoverReport {
            term: self.current_term,
            membership_epoch: self.membership_epoch,
            next_slot: self.next_slot,
            recovered_slots,
            filled_gaps,
            pending_removed_fence_nodes,
        })
    }

    /// Shared activation receipt verifier used by BOTH local `activate_membership_transition()`
    /// and remote TCP RPC coordinators!
    ///
    /// Enforces:
    /// - No duplicate voter identities (never counts one voter twice).
    /// - Every receipt belongs to `prev_cfg` or `mdec.proposal.new_members` and has
    ///   `barrier_slot == mdec.proposal.slot`.
    /// - Every embedded `post_transition_old_locks` record is cryptographically validated (identity,
    ///   epoch, slot > transition slot, proposal digest, Ed25519 signature) and blocks activation
    ///   even if remaining voters would otherwise satisfy both quorum counts!
    /// - Requires BOTH `fenced_old >= Q(C_old)` AND `activated_new >= Q(C_new)` with
    ///   `min_active_epoch >= mdec.proposal.next_epoch`.
    pub fn verify_activation_receipts(
        &self,
        mdec: &MembershipTransitionDecision,
        prev_cfg: &MembershipEpochConfig,
        receipts: &[EpochInstallReceipt],
    ) -> Result<Vec<String>> {
        let new_member_ids: HashSet<&str> = mdec
            .proposal
            .new_members
            .iter()
            .map(|m| m.node_id.as_str())
            .collect();
        let mut seen_voters = HashSet::new();
        let mut fenced_old = HashSet::new();
        let mut activated_new = HashSet::new();
        let mut unresolved_post_transition: Vec<(String, Vec<u64>)> = Vec::new();

        for receipt in receipts {
            if !seen_voters.insert(receipt.voter_node_id.as_str()) {
                anyhow::bail!(
                    "Duplicate EpochInstallReceipt from voter '{}' during epoch {} activation",
                    receipt.voter_node_id,
                    mdec.proposal.next_epoch
                );
            }
            let in_old = prev_cfg.members.contains_key(&receipt.voter_node_id);
            let in_new = new_member_ids.contains(receipt.voter_node_id.as_str());
            if !in_old && !in_new {
                anyhow::bail!(
                    "Unauthorized EpochInstallReceipt from non-member voter '{}'",
                    receipt.voter_node_id
                );
            }
            if receipt.barrier_slot != mdec.proposal.slot {
                anyhow::bail!(
                    "EpochInstallReceipt from '{}' has barrier_slot {} != expected transition slot {}",
                    receipt.voter_node_id,
                    receipt.barrier_slot,
                    mdec.proposal.slot
                );
            }

            // Cryptographically validate every reported unresolved post-transition old-epoch lock!
            for lock in &receipt.post_transition_old_locks {
                if lock.epoch != mdec.proposal.prev_epoch || lock.slot <= mdec.proposal.slot {
                    anyhow::bail!(
                        "Malformed post_transition_old_lock from '{}': (epoch={}, slot={}) invalid for transition (prev_epoch={}, slot={})",
                        receipt.voter_node_id,
                        lock.epoch,
                        lock.slot,
                        mdec.proposal.prev_epoch,
                        mdec.proposal.slot
                    );
                }
                let computed = lock.proposal.validate_for_vote(
                    &mdec.proposal.group_id,
                    lock.epoch,
                    lock.slot,
                )?;
                if computed != lock.proposal_hash {
                    anyhow::bail!(
                        "Tampered post_transition_old_lock proposal from '{}' at slot {}",
                        receipt.voter_node_id,
                        lock.slot
                    );
                }
                let v = &lock.vote;
                if v.group_id != mdec.proposal.group_id
                    || v.epoch != lock.epoch
                    || v.term != lock.accepted_term
                    || v.slot != lock.slot
                    || v.proposal_hash != lock.proposal_hash
                    || v.voter_node_id != receipt.voter_node_id
                {
                    anyhow::bail!(
                        "Mismatched embedded vote in post_transition_old_lock from '{}' at slot {}",
                        receipt.voter_node_id,
                        lock.slot
                    );
                }
                let old_member = prev_cfg.members.get(&receipt.voter_node_id).ok_or_else(|| {
                    anyhow!(
                        "Post-transition old-epoch lock reported by non-old-epoch voter '{}'",
                        receipt.voter_node_id
                    )
                })?;
                let vpayload = canonical_vote_payload_for_term(
                    &v.group_id,
                    v.epoch,
                    v.term,
                    v.slot,
                    &v.proposal_hash,
                    &v.voter_node_id,
                );
                if !nexus_db::auth::ed25519_verify(&old_member.ed25519_pubkey, &vpayload, &v.signature) {
                    anyhow::bail!(
                        "Invalid Ed25519 signature on post_transition_old_lock from '{}' at slot {}",
                        receipt.voter_node_id,
                        lock.slot
                    );
                }
            }

            if !receipt.post_transition_old_locks.is_empty() {
                let slots: Vec<u64> = receipt
                    .post_transition_old_locks
                    .iter()
                    .map(|l| l.slot)
                    .collect();
                unresolved_post_transition.push((receipt.voter_node_id.clone(), slots));
                continue;
            }

            if receipt.min_active_epoch >= mdec.proposal.next_epoch {
                if in_old {
                    fenced_old.insert(receipt.voter_node_id.clone());
                }
                if in_new {
                    activated_new.insert(receipt.voter_node_id.clone());
                }
            }
        }

        if !unresolved_post_transition.is_empty() {
            anyhow::bail!(
                "Membership transition to epoch {} (slot={}) BLOCKED: unresolved post-transition old-epoch accepted locks exist on voters {:?} — must recover/reconcile before activation!",
                mdec.proposal.next_epoch,
                mdec.proposal.slot,
                unresolved_post_transition
            );
        }

        let req_old = prev_cfg.mode.quorum_size(prev_cfg.members.len());
        if fenced_old.len() < req_old {
            anyhow::bail!(
                "Membership transition to epoch {} CANNOT activate safely: only {}/{} old-configuration voters durably fenced (need >= {} to prevent old-epoch split-brain)",
                mdec.proposal.next_epoch,
                fenced_old.len(),
                prev_cfg.members.len(),
                req_old
            );
        }

        let req_new = mdec.proposal.mode.quorum_size(mdec.proposal.new_members.len());
        if activated_new.len() < req_new {
            anyhow::bail!(
                "Membership transition to epoch {} FAILED installation: only {}/{} new-configuration voters installed it (need >= {})",
                mdec.proposal.next_epoch,
                activated_new.len(),
                mdec.proposal.new_members.len(),
                req_new
            );
        }

        let mut pending_removed = Vec::new();
        for old_id in prev_cfg.members.keys() {
            if !new_member_ids.contains(old_id.as_str()) && !fenced_old.contains(old_id) {
                pending_removed.push(old_id.clone());
            }
        }
        pending_removed.sort();
        Ok(pending_removed)
    }

    /// Dual-quorum membership activation & old-configuration fencing barrier delegating directly
    /// to `verify_activation_receipts()`.
    pub async fn activate_membership_transition(
        &self,
        mdec: &MembershipTransitionDecision,
        prev_cfg: &MembershipEpochConfig,
        voters: &[VoterNode],
    ) -> Result<Vec<String>> {
        let new_member_ids: HashSet<&str> = mdec
            .proposal
            .new_members
            .iter()
            .map(|m| m.node_id.as_str())
            .collect();
        let mut receipts = Vec::new();

        for v in voters {
            let in_old = prev_cfg.members.contains_key(&v.node_id);
            let in_new = new_member_ids.contains(v.node_id.as_str());
            if !in_old && !in_new {
                continue;
            }
            if let Ok(receipt) = v.install_membership_epoch(mdec, prev_cfg).await {
                receipts.push(receipt);
            }
        }

        self.verify_activation_receipts(mdec, prev_cfg, &receipts)
    }

    /// Commit a quorum-certified membership transition using the unified `SlotProposal::Membership`
    /// durable voting contract (atomic 3-record persistence: decision log + epoch history + tip).
    pub async fn reconfigure_membership_with_quorum(
        &mut self,
        proposal: &MembershipTransitionProposal,
        votes: Vec<SignedVote>,
    ) -> Result<MembershipTransitionDecision> {
        if proposal.group_id != self.group_id {
            anyhow::bail!(
                "Membership transition group_id '{}' does not match '{}'",
                proposal.group_id,
                self.group_id
            );
        }
        if proposal.prev_epoch != self.membership_epoch
            || proposal.next_epoch != self.membership_epoch + 1
        {
            anyhow::bail!(
                "Membership transition epoch ({} -> {}) does not match active epoch {}",
                proposal.prev_epoch,
                proposal.next_epoch,
                self.membership_epoch
            );
        }
        if proposal.slot != self.next_slot {
            anyhow::bail!(
                "Membership transition slot {} does not match expected next_slot {}",
                proposal.slot,
                self.next_slot
            );
        }
        if proposal.mode != self.mode {
            anyhow::bail!(
                "Membership transition mode {:?} does not match group mode {:?}",
                proposal.mode,
                self.mode
            );
        }
        let expected_hash = proposal.canonical_digest()?;
        let slot = proposal.slot;
        let vote_term = votes
            .iter()
            .filter(|v| {
                v.group_id == self.group_id
                    && v.epoch == self.membership_epoch
                    && v.slot == slot
                    && v.proposal_hash == expected_hash
            })
            .map(|v| v.term)
            .max()
            .unwrap_or(self.current_term);
        if vote_term < self.current_term {
            anyhow::bail!(
                "Stale-term membership transition (vote_term={} < current_term={}) rejected",
                vote_term,
                self.current_term
            );
        }

        let mut valid_votes = Vec::new();
        let mut unique = HashSet::new();
        for v in votes {
            if v.group_id == self.group_id
                && v.epoch == self.membership_epoch
                && v.term == vote_term
                && v.slot == slot
                && v.proposal_hash == expected_hash
                && unique.insert(v.voter_node_id.clone())
            {
                valid_votes.push(v);
            }
        }
        let qc = QuorumCertificate {
            group_id: self.group_id.clone(),
            epoch: self.membership_epoch,
            term: vote_term,
            slot,
            proposal_hash: expected_hash,
            mode: self.mode,
            votes: valid_votes,
        };
        let mut canonical_prop = proposal.clone();
        canonical_prop.new_members.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        let decision = MembershipTransitionDecision {
            proposal: canonical_prop,
            qc,
        };
        self.validate_durable_membership_decision(&decision, Some(slot))?;

        let new_next_slot = self.next_slot + 1;
        self.persist_membership_transition_atomic(&decision, new_next_slot)
            .await?;

        self.current_term = self.current_term.max(vote_term);
        self.membership_epoch = decision.proposal.next_epoch;
        self.next_slot = new_next_slot;
        let new_map: HashMap<String, GroupMember> = decision
            .proposal
            .new_members
            .iter()
            .cloned()
            .map(|m| (m.node_id.clone(), m))
            .collect();
        self.membership_history.insert(
            decision.proposal.next_epoch,
            MembershipEpochConfig {
                mode: decision.proposal.mode,
                members: new_map.clone(),
            },
        );
        self.members = new_map;
        Ok(decision)
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
        let payload = canonical_vote_payload_for_term(
            &vote.group_id,
            vote.epoch,
            vote.term,
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
        let current_cfg = MembershipEpochConfig {
            mode: self.mode,
            members: self.members.clone(),
        };
        self.verify_qc_for_epoch(qc, &current_cfg, self.membership_epoch)
    }

    pub fn verify_qc_for_epoch(
        &self,
        qc: &QuorumCertificate,
        config: &MembershipEpochConfig,
        expected_epoch: u64,
    ) -> Result<()> {
        if qc.group_id != self.group_id || qc.mode != config.mode || qc.epoch != expected_epoch {
            anyhow::bail!(
                "QC mismatch: expected (group={}, epoch={}, mode={:?}), got (group={}, epoch={}, mode={:?})",
                self.group_id,
                expected_epoch,
                config.mode,
                qc.group_id,
                qc.epoch,
                qc.mode
            );
        }
        let mut unique_voters = HashSet::new();
        for v in &qc.votes {
            if v.group_id != qc.group_id
                || v.epoch != qc.epoch
                || v.term != qc.term
                || v.slot != qc.slot
                || v.proposal_hash != qc.proposal_hash
            {
                anyhow::bail!("QC contains mismatched vote");
            }
            let member = config
                .members
                .get(&v.voter_node_id)
                .ok_or_else(|| anyhow!("QC voter '{}' not in group for epoch {}", v.voter_node_id, expected_epoch))?;
            let payload = canonical_vote_payload_for_term(
                &v.group_id,
                v.epoch,
                v.term,
                v.slot,
                &v.proposal_hash,
                &v.voter_node_id,
            );
            if !nexus_db::auth::ed25519_verify(&member.ed25519_pubkey, &payload, &v.signature) {
                anyhow::bail!("QC contains invalid signature from '{}'", v.voter_node_id);
            }
            unique_voters.insert(v.voter_node_id.clone());
        }
        let required = config.mode.quorum_size(config.members.len());
        if unique_voters.len() < required {
            anyhow::bail!(
                "Insufficient quorum for {:?}: got {} valid votes, need {}",
                config.mode,
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
        if now >= expires_at_ms {
            anyhow::bail!(
                "Cannot commit already-expired lease '{}' (expires_at_ms={} <= now={})",
                lease_id,
                expires_at_ms,
                now
            );
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

        let vote_term = votes
            .iter()
            .filter(|v| v.slot == slot && v.proposal_hash == expected_hash)
            .map(|v| v.term)
            .max()
            .unwrap_or(self.current_term);
        if vote_term < self.current_term {
            anyhow::bail!(
                "Stale-term lease commit (vote_term={} < current_term={}) rejected",
                vote_term,
                self.current_term
            );
        }

        let mut valid_votes = Vec::new();
        let mut unique_voters = HashSet::new();
        for v in votes {
            if v.slot != slot || v.proposal_hash != expected_hash || v.term != vote_term {
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
            term: vote_term,
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
        self.current_term = self.current_term.max(vote_term);
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
