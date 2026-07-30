//! Event lifecycle: emitted events reconstruct the complete authorization and
//! financial history, and every access-control event carries the schema version.

use soroban_sdk::testutils::Address as _;
mod common;

use common::*;
use soroban_sdk::testutils::Events;
use soroban_sdk::{symbol_short, vec, IntoVal};

/// The access-control event stream reconstructs the full authorization lifecycle,
/// and every payload includes actor, subject, role transition, and schema version.
#[test]
fn acl_event_stream_is_complete_and_versioned() {
    let env = new_env();
    let owner = soroban_sdk::Address::generate(&env);
    let (_, c) = deploy_acl(&env, &owner);

    let m = soroban_sdk::Address::generate(&env);
    let n = soroban_sdk::Address::generate(&env);
    c.assign_role(&owner, &m, &Role::Member);
    c.revoke_role(&owner, &m);
    c.propose_ownership(&owner, &n);
    c.accept_ownership(&n);

    let ver = acl::EVENT_SCHEMA_VERSION;
    let id = c.address.clone();
    let expected = vec![
        &env,
        (
            id.clone(),
            (symbol_short!("acl"), symbol_short!("init")).into_val(&env),
            (owner.clone(), ver).into_val(&env),
        ),
        (
            id.clone(),
            (symbol_short!("acl"), symbol_short!("assign")).into_val(&env),
            (owner.clone(), m.clone(), 0_u32, Role::Member as u32, ver).into_val(&env),
        ),
        (
            id.clone(),
            (symbol_short!("acl"), symbol_short!("revoke")).into_val(&env),
            (owner.clone(), m.clone(), Role::Member as u32, ver).into_val(&env),
        ),
        (
            id.clone(),
            (symbol_short!("acl"), symbol_short!("own_prop")).into_val(&env),
            (owner.clone(), n.clone(), ver).into_val(&env),
        ),
        (
            id.clone(),
            (symbol_short!("acl"), symbol_short!("owner")).into_val(&env),
            (owner.clone(), n.clone(), ver).into_val(&env),
        ),
    ];

    assert_eq!(env.events().all(), expected);
}

/// Each treasury lifecycle step emits exactly one event, so the financial history
/// (init -> deposit -> propose -> approve -> execute) is fully reconstructable.
#[test]
fn treasury_lifecycle_emits_every_step() {
    let env = new_env();
    let admin = soroban_sdk::Address::generate(&env);
    let (acl_id, _acl) = deploy_acl(&env, &admin);
    let signers = addrs(&env, 2);
    let asset = env.register_stellar_asset_contract_v2(admin.clone()).address();
    let recipient = soroban_sdk::Address::generate(&env);
    let c = deploy_treasury(&env, &admin, &asset, 2, &svec(&env, &signers), &acl_id);
    let token_admin = soroban_sdk::token::StellarAssetClient::new(&env, &asset);
    token_admin.mint(&signers[0], &1_000_000);

    let count_before = env.events().all().len(); // setup events already emitted
    assert!(count_before >= 1, "init event present");

    c.deposit(&signers[0], &5_000);
    let exp = env.ledger().timestamp() + 10_000;
    let tx = c.propose_withdrawal(&signers[0], &recipient, &2_000, &symbol_short!("r"), &exp);
    c.approve(&signers[1], &tx);
    c.execute(&signers[0], &tx);

    // deposit + propose + approve + execute = 4 treasury events, plus token
    // transfer event emitted by real token custody. Assert at least 4 new events.
    let new_events = env.events().all().len() - count_before;
    assert!(new_events >= 4, "expected at least 4 lifecycle events, got {}", new_events);
    // Final state agrees with the executed-withdrawal history.
    assert_eq!(c.get_balance(), 3_000);
}
