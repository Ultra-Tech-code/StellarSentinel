//! Shared harness for the cross-contract invariant suite.
//!
//! Provides deterministic sequencing (a seeded LCG), contract deployment helpers,
//! ledger-clock helpers, and reusable invariant assertions. Functional sequences
//! use blanket auth; authorization is proven separately with selective `mock_auths`
//! in the access-control unit tests and in `cross_contract_invariants.rs`.

#![allow(dead_code)]

use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{Address, Env, Vec};

pub use stellar_sentinel_access_control as acl;
pub use stellar_sentinel_governance as governance;
pub use stellar_sentinel_token_vault as vault;
pub use stellar_sentinel_treasury as treasury;

pub use acl::{AccessControlContract, AccessControlContractClient, Role};
pub use governance::{
    GovernanceContract, GovernanceContractClient, ProposalAction, ProposalStatus,
};
pub use treasury::{TreasuryContract, TreasuryContractClient};
pub use vault::{TokenVaultContract, TokenVaultContractClient};

// ---------------------------------------------------------------------------
// Environment & randomness
// ---------------------------------------------------------------------------

/// Fresh env with blanket auth for functional sequences.
pub fn new_env() -> Env {
    let env = Env::default();
    env.mock_all_auths();
    // Start the clock past zero so "expired/active" comparisons are meaningful.
    env.ledger().set_timestamp(1_000);
    env.ledger().set_sequence_number(10);
    env
}

/// Generate `n` fresh addresses.
pub fn addrs(env: &Env, n: usize) -> std::vec::Vec<Address> {
    (0..n).map(|_| Address::generate(env)).collect()
}

/// Build a Soroban `Vec<Address>` from a slice.
pub fn svec(env: &Env, items: &[Address]) -> Vec<Address> {
    let mut v = Vec::new(env);
    for a in items {
        v.push_back(a.clone());
    }
    v
}

/// Deterministic 64-bit LCG (Knuth/MMIX constants). Reproducible across runs,
/// so a failing sequence is always replayable from its seed.
pub struct Rng(pub u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    /// Uniform value in `[0, n)`.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }
    pub fn flip(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
}

// ---------------------------------------------------------------------------
// Ledger clock helpers
// ---------------------------------------------------------------------------

pub fn set_time(env: &Env, t: u64) {
    env.ledger().set_timestamp(t);
}
pub fn advance_time(env: &Env, by: u64) {
    let t = env.ledger().timestamp();
    env.ledger().set_timestamp(t + by);
}
pub fn advance_seq(env: &Env, by: u32) {
    let s = env.ledger().sequence();
    env.ledger().set_sequence_number(s + by);
}

// ---------------------------------------------------------------------------
// Deployment helpers
// ---------------------------------------------------------------------------

pub fn deploy_acl(env: &Env, owner: &Address) -> (Address, AccessControlContractClient<'static>) {
    let id = env.register_contract(None, AccessControlContract);
    let c = AccessControlContractClient::new(env, &id);
    c.initialize(owner);
    (id, c)
}

pub fn deploy_treasury(
    env: &Env,
    admin: &Address,
    asset: &Address,
    threshold: u32,
    signers: &Vec<Address>,
    acl_id: &Address,
) -> TreasuryContractClient<'static> {
    let id = env.register_contract(None, TreasuryContract);
    let c = TreasuryContractClient::new(env, &id);
    c.initialize(admin, asset, &threshold, signers, acl_id);
    c
}

pub fn deploy_governance(
    env: &Env,
    admin: &Address,
    members: &Vec<Address>,
    quorum_percent: u32,
    voting_period: u32,
    acl_id: &Address,
    treasury_id: &Address,
) -> GovernanceContractClient<'static> {
    let id = env.register_contract(None, GovernanceContract);
    let c = GovernanceContractClient::new(env, &id);
    c.initialize(admin, members, &quorum_percent, &voting_period, acl_id, treasury_id);
    c
}

pub fn deploy_vault(
    env: &Env,
    admin: &Address,
    asset: &Address,
    emergency_signers: &Vec<Address>,
    emergency_threshold: u32,
    acl_id: &Address,
) -> TokenVaultContractClient<'static> {
    let id = env.register_contract(None, TokenVaultContract);
    let c = TokenVaultContractClient::new(env, &id);
    c.initialize(admin, asset, emergency_signers, &emergency_threshold, acl_id);
    c
}

// ---------------------------------------------------------------------------
// Reusable invariant assertions (each names the invariant it guards)
// ---------------------------------------------------------------------------

/// INV-T1/T2/T5: balance non-negative, equals deposits minus withdrawals, and the
/// approval threshold stays within `[1, signer_count]`.
pub fn assert_treasury_invariants(
    c: &TreasuryContractClient,
    deposited: i128,
    withdrawn: i128,
) {
    let cfg = c.get_config();
    assert!(cfg.balance >= 0, "INV-T1 treasury balance must be non-negative");
    assert_eq!(
        cfg.balance,
        deposited - withdrawn,
        "INV-T2 balance must equal deposits minus executed withdrawals"
    );
    assert!(
        cfg.threshold >= 1 && cfg.threshold <= cfg.signer_count,
        "INV-T5 threshold must stay within [1, signer_count]"
    );
}

/// INV-V1: locked liabilities are non-negative and exactly match tracked assets.
pub fn assert_vault_locked(env: &Env, c: &TokenVaultContractClient, asset: &Address, expected_locked: i128) {
    let stats = c.get_stats();
    assert!(stats.total_locked >= 0, "INV-V1 total_locked must be non-negative");
    assert_eq!(
        stats.total_locked, expected_locked,
        "INV-V1 total_locked must equal outstanding lock + vesting liabilities"
    );
    let bal = soroban_sdk::token::Client::new(env, asset).balance(&c.address);
    assert_eq!(bal, expected_locked, "INV-V1 vault balance must equal total_locked");
}

/// INV-A1: exactly one Owner exists, and per-role counts equal the number of
/// addresses actually holding each role.
pub fn assert_acl_consistent(c: &AccessControlContractClient) {
    let summary = c.get_summary();
    assert_eq!(summary.owner_count, 1, "INV-A1 exactly one owner must exist");

    let assignments = c.get_all_assignments();
    let (mut o, mut a, mut m, mut v) = (0u32, 0u32, 0u32, 0u32);
    for i in 0..assignments.len() {
        match assignments.get(i).unwrap().role {
            Role::Owner => o += 1,
            Role::Admin => a += 1,
            Role::Member => m += 1,
            Role::Viewer => v += 1,
        }
    }
    assert_eq!(o, summary.owner_count, "INV-A2 owner count matches assignments");
    assert_eq!(a, summary.admin_count, "INV-A2 admin count matches assignments");
    assert_eq!(m, summary.member_count, "INV-A2 member count matches assignments");
    assert_eq!(v, summary.viewer_count, "INV-A2 viewer count matches assignments");
    assert_eq!(
        assignments.len(),
        summary.total_members,
        "INV-A2 total members matches assignment list"
    );
}
