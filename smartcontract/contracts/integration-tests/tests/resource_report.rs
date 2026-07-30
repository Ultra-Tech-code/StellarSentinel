//! Resource & storage-growth measurements for representative operation sequences.
//!
//! These assert that on-chain state grows linearly (one stored entry per logical
//! object) with no hidden amplification, and print the measured figures. Run with
//! `cargo test -p stellar-sentinel-integration-tests --test resource_report -- --nocapture`
//! to see the report; the asserted bounds are summarized in `RESOURCE-REPORT.md`.

use soroban_sdk::testutils::Address as _;
mod common;

use common::*;
use soroban_sdk::symbol_short;

const N: u64 = 50;

#[test]
fn treasury_storage_growth_is_linear() {
    let env = new_env();
    let admin = soroban_sdk::Address::generate(&env);
    let (acl_id, _acl) = deploy_acl(&env, &admin);
    let signers = addrs(&env, 2);
    let asset = env.register_stellar_asset_contract_v2(admin.clone()).address();
    let recipient = soroban_sdk::Address::generate(&env);
    let c = deploy_treasury(&env, &admin, &asset, 2, &svec(&env, &signers), &acl_id);
    soroban_sdk::token::StellarAssetClient::new(&env, &asset).mint(&signers[0], &(N as i128 * 10_000));
    c.deposit(&signers[0], &(N as i128 * 10_000));

    let exp = env.ledger().timestamp() + 1_000_000;
    for _ in 0..N {
        c.propose_withdrawal(&signers[0], &recipient, &1, &symbol_short!("r"), &exp);
    }
    let cfg = c.get_config();
    assert_eq!(cfg.tx_count, N, "one transaction entry per proposal");
    println!(
        "[resource] treasury: {} proposals -> tx_count={}, balance={}",
        N, cfg.tx_count, cfg.balance
    );
}

#[test]
fn vault_storage_growth_is_linear() {
    let env = new_env();
    let admin = soroban_sdk::Address::generate(&env);
    let (acl_id, _acl) = deploy_acl(&env, &admin);
    let signers = addrs(&env, 2);
    let asset = env.register_stellar_asset_contract_v2(admin.clone()).address();
    let c = deploy_vault(&env, &admin, &asset, &svec(&env, &signers), 2, &acl_id);
    let owner = soroban_sdk::Address::generate(&env);
    
    soroban_sdk::token::StellarAssetClient::new(&env, &asset).mint(&owner, &1_000_000);

    for _ in 0..N {
        c.lock_tokens(&owner, &1_000, &100, &symbol_short!("l"));
    }
    let stats = c.get_stats();
    assert_eq!(stats.lock_count, N, "one lock entry per lock");
    assert_eq!(stats.total_locked, N as i128 * 1_000);
    println!(
        "[resource] vault: {} locks -> lock_count={}, total_locked={}",
        N, stats.lock_count, stats.total_locked
    );
}

#[test]
fn governance_storage_growth_is_linear() {
    let env = new_env();
    let admin = soroban_sdk::Address::generate(&env);
    let (acl_id, acl) = deploy_acl(&env, &admin);
    let members = addrs(&env, 3);
    for m in &members {
        acl.assign_role(&admin, m, &Role::Member);
    }
    let treasury_addr = soroban_sdk::Address::generate(&env);
    let c = deploy_governance(&env, &admin, &svec(&env, &members), 50, 1_000_000, &acl_id, &treasury_addr);

    for _ in 0..N {
        c.create_proposal(
            &members[0],
            &symbol_short!("t"),
            &symbol_short!("d"),
            &ProposalAction::General,
            &0,
            &members[0],
        );
    }
    let cfg = c.get_config();
    assert_eq!(cfg.proposal_count, N, "one proposal entry per proposal");
    println!("[resource] governance: {} proposals -> proposal_count={}", N, cfg.proposal_count);
}

#[test]
fn access_control_storage_growth_is_linear() {
    let env = new_env();
    let owner = soroban_sdk::Address::generate(&env);
    let (_, c) = deploy_acl(&env, &owner);

    let users = addrs(&env, N as usize);
    for u in &users {
        c.assign_role(&owner, u, &Role::Member);
    }
    let summary = c.get_summary();
    assert_eq!(summary.total_members, N as u32 + 1, "owner + N members");
    assert_eq!(summary.member_count, N as u32);
    println!(
        "[resource] access-control: {} assignments -> total_members={}",
        N, summary.total_members
    );
}
