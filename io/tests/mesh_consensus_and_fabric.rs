//! Final Acceptance Gate Regression Suite (Resource Trust, Lease Binding, Legacy/Conflict Fail-Closed)

use nexus_io::db::Database;
use nexus_io::iam::idp::{NexusIdp, OrgPolicyPatch};
use nexus_io::mesh::consensus::{
    hash_lease_proposal, hash_membership_change, sign_vote_raw, ConsensusMode, CoordinationGroup,
    FencedLease, FencedResourceGuard, GroupMember, LeaseProposal, QuorumCertificate, VoteRequest,
    VoterNode,
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

    let voter_a = VoterNode::new("node-a", sk_a.clone(), Arc::new(Database::open_mem()));
    let voter_b = VoterNode::new("node-b", sk_b.clone(), Arc::new(Database::open_mem()));
    let voter_c = VoterNode::new("node-c", sk_c.clone(), Arc::new(Database::open_mem()));
    let voter_d = VoterNode::new("node-d", sk_d.clone(), Arc::new(Database::open_mem()));
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
        proposal: Some(bad_prop),
    };
    assert!(
        voter_a.cast_vote(&tampered_vote_req).await.is_err(),
        "Voter MUST reject VoteRequest when proposal payload does not match proposal_hash!"
    );

    // 4. Legacy voter locks missing `proposal: None` MUST fail closed on autonomous recovery!
    let legacy_hash = hash_lease_proposal("pool:us-east", "lse_leg", "gpu:legacy", "node-b", "wl-leg", 1, t0, t0 + 30_000);
    let legacy_req = VoteRequest {
        group_id: "pool:us-east".into(),
        epoch: 1,
        slot: 60,
        proposal_hash: legacy_hash,
        proposal: None, // Legacy lock without proposal payload
    };
    let lv1 = voter_a.cast_vote(&legacy_req).await.unwrap();
    let lv2 = voter_b.cast_vote(&legacy_req).await.unwrap();
    let lv3 = voter_c.cast_vote(&legacy_req).await.unwrap();
    let mut rec_group = CoordinationGroup::new("pool:us-east", ConsensusMode::CftFastPath, members.clone());
    assert!(
        rec_group
            .recover_and_commit_slot(60, vec![(lv1, None), (lv2, None), (lv3, None)])
            .await
            .is_err(),
        "Autonomous recovery MUST fail closed when legacy voter locks lack LeaseProposal!"
    );

    // 5. Conflicting durable decisions in `sys_mesh_decision_log` MUST fail closed!
    let conflict_db = Arc::new(Database::open_mem());
    let mut conflict_grp = CoordinationGroup::open_durable(
        conflict_db.clone(),
        "pool:conflict",
        ConsensusMode::CftFastPath,
        members.clone(),
    )
    .await
    .unwrap();
    let l_a = FencedLease {
        lease_id: "lse_a".into(),
        group_id: "pool:conflict".into(),
        resource_key: "r1".into(),
        holder_node_id: "node-a".into(),
        workload_id: "w1".into(),
        fencing_epoch: 1,
        issued_at_ms: t0,
        expires_at_ms: t0 + 30_000,
        qc: QuorumCertificate {
            group_id: "pool:conflict".into(),
            epoch: 1,
            slot: 7,
            proposal_hash: hash_lease_proposal("pool:conflict", "lse_a", "r1", "node-a", "w1", 1, t0, t0 + 30_000),
            mode: ConsensusMode::CftFastPath,
            votes: vec![],
        },
    };
    let l_b = FencedLease {
        lease_id: "lse_b".into(),
        holder_node_id: "node-b".into(),
        ..l_a.clone()
    };
    conflict_db.client.query("CREATE type::record('sys_mesh_decision_log', 'corrupt_a') CONTENT $l;").bind(("l", serde_json::to_value(&l_a).unwrap())).await.unwrap();
    conflict_db.client.query("CREATE type::record('sys_mesh_decision_log', 'corrupt_b') CONTENT $l;").bind(("l", serde_json::to_value(&l_b).unwrap())).await.unwrap();
    assert!(
        conflict_grp.recover_and_commit_slot(7, vec![]).await.is_err(),
        "Conflicting durable decision-log records for slot 7 MUST fail closed!"
    );

    // 6. Membership-transition digest & BFT equivocation
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
