//! Cross-contract security invariants: authorization consistency, membership
//! lifecycle, and terminal-operation replay resistance across all four contracts.

use soroban_sdk::testutils::Address as _;
mod common;

use common::*;
use soroban_sdk::symbol_short;

/// Privileged actions are gated consistently: the role an account holds in
/// access-control lines up with what the treasury lets it do. A plain member can
/// neither administer nor propose withdrawals (INV-X1).
#[test]
fn role_decisions_gate_privileged_treasury_actions() {
    let env = new_env();
    let owner = soroban_sdk::Address::generate(&env);
    let admin = soroban_sdk::Address::generate(&env);
    let member = soroban_sdk::Address::generate(&env);

    let (acl_id, acl) = deploy_acl(&env, &owner);
    acl.assign_role(&owner, &admin, &Role::Admin);
    acl.assign_role(&owner, &member, &Role::Member);

    assert_eq!(acl.is_admin_or_above(&owner), true);
    assert_eq!(acl.is_admin_or_above(&admin), true);
    assert_eq!(acl.is_admin_or_above(&member), false);
    assert_eq!(acl.is_owner(&member), false);

    let members = addrs(&env, 2);
    for m in &members {
        acl.assign_role(&owner, m, &Role::Member);
    }

    let newbie = soroban_sdk::Address::generate(&env);
    
    let signers = addrs(&env, 2);
    let asset = env.register_stellar_asset_contract_v2(owner.clone()).address();
    let treasury = deploy_treasury(&env, &owner, &asset, 1, &svec(&env, &signers), &acl_id);
    let gov = deploy_governance(&env, &owner, &svec(&env, &members), 34, 50, &acl_id, &treasury.address);
    
    let token_admin = soroban_sdk::token::StellarAssetClient::new(&env, &asset);
    token_admin.mint(&signers[0], &10_000);
    treasury.deposit(&signers[0], &10_000);

    assert_eq!(
        treasury.try_set_threshold(&member, &1),
        Err(Ok(treasury::Error::Unauthorized))
    );
    let exp = env.ledger().timestamp() + 10_000;
    assert_eq!(
        treasury.try_propose_withdrawal(&member, &member, &1_000, &symbol_short!("x"), &exp),
        Err(Ok(treasury::Error::NotASigner))
    );
    assert_acl_consistent(&acl);
    assert_treasury_invariants(&treasury, 10_000, 0);
}

/// Governance membership churn updates authorization with no stale rights: an added
/// member can act, and a removed member immediately cannot (INV-X2).
#[test]
fn governance_membership_lifecycle_updates_authorization() {
    let env = new_env();
    let admin = soroban_sdk::Address::generate(&env);
    let (acl_id, _acl) = deploy_acl(&env, &admin);
    let members = addrs(&env, 3);
    for m in &members {
        _acl.assign_role(&admin, m, &Role::Member);
    }
    let treasury_addr = soroban_sdk::Address::generate(&env);
    let gov = deploy_governance(&env, &admin, &svec(&env, &members), 34, 50, &acl_id, &treasury_addr);

    let newbie = soroban_sdk::Address::generate(&env);
    assert_eq!(
        gov.try_create_proposal(
            &newbie,
            &symbol_short!("t"),
            &symbol_short!("d"),
            &ProposalAction::General,
            &0,
            &newbie,
        ),
        Err(Ok(governance::Error::NotAMember))
    );

    let add = gov.create_proposal(
        &members[0],
        &symbol_short!("add"),
        &symbol_short!("d"),
        &ProposalAction::AddMember,
        &0,
        &newbie,
    );
    gov.vote(&members[0], &add, &true);
    advance_seq(&env, 100);
    assert_eq!(gov.finalize(&members[0], &add), ProposalStatus::Passed);
    gov.execute_proposal(&admin, &add);
    _acl.assign_role(&admin, &newbie, &Role::Member);
    assert_eq!(gov.get_config().member_count, 4);

    let p = gov.create_proposal(
        &newbie,
        &symbol_short!("p"),
        &symbol_short!("d"),
        &ProposalAction::General,
        &0,
        &newbie,
    );
    gov.vote(&newbie, &p, &true);

    let rem = gov.create_proposal(
        &members[0],
        &symbol_short!("rem"),
        &symbol_short!("d"),
        &ProposalAction::RemoveMember,
        &0,
        &members[1],
    );
    gov.vote(&members[0], &rem, &true);
    advance_seq(&env, 100);
    assert_eq!(gov.finalize(&members[0], &rem), ProposalStatus::Passed);
    gov.execute_proposal(&admin, &rem);
    _acl.revoke_role(&admin, &members[1]);
    assert_eq!(gov.get_config().member_count, 3);

    assert_eq!(
        gov.try_create_proposal(
            &members[1],
            &symbol_short!("t"),
            &symbol_short!("d"),
            &ProposalAction::General,
            &0,
            &members[1],
        ),
        Err(Ok(governance::Error::NotAMember))
    );
}

/// Terminal operations in every contract are one-shot: once settled they cannot be
/// replayed (INV-X3, reinforcing INV-T3 / INV-G5 / INV-V6).
#[test]
fn terminal_operations_cannot_replay_across_contracts() {
    let env = new_env();

    let admin = soroban_sdk::Address::generate(&env);
    let (acl_id, _acl) = deploy_acl(&env, &admin);

    let signers = addrs(&env, 2);
    let asset = env.register_stellar_asset_contract_v2(admin.clone()).address();
    let recipient = soroban_sdk::Address::generate(&env);
    let treasury = deploy_treasury(&env, &admin, &asset, 2, &svec(&env, &signers), &acl_id);
    let token_admin = soroban_sdk::token::StellarAssetClient::new(&env, &asset);
    token_admin.mint(&signers[0], &10_000);
    treasury.deposit(&signers[0], &10_000);
    soroban_sdk::token::StellarAssetClient::new(&env, &asset).mint(&treasury.address, &10_000);
    let exp = env.ledger().timestamp() + 10_000;
    let tx = treasury.propose_withdrawal(&signers[0], &recipient, &4_000, &symbol_short!("r"), &exp);
    treasury.approve(&signers[1], &tx);
    treasury.execute(&signers[0], &tx);
    assert_eq!(
        treasury.try_execute(&signers[0], &tx),
        Err(Ok(treasury::Error::AlreadyExecuted))
    );

    let gmembers = addrs(&env, 3);
    for m in &gmembers {
        _acl.assign_role(&admin, m, &Role::Member);
    }
    let gov = deploy_governance(&env, &admin, &svec(&env, &gmembers), 34, 50, &acl_id, &treasury.address);
    let pid = gov.create_proposal(
        &gmembers[0],
        &symbol_short!("t"),
        &symbol_short!("d"),
        &ProposalAction::General,
        &0,
        &gmembers[0],
    );
    gov.vote(&gmembers[0], &pid, &true);
    advance_seq(&env, 100);
    gov.finalize(&gmembers[0], &pid);
    gov.execute_proposal(&admin, &pid);
    assert_eq!(
        gov.try_execute_proposal(&admin, &pid),
        Err(Ok(governance::Error::ProposalRejected))
    );

    let esigners = addrs(&env, 2);
    for s in &esigners {
        _acl.assign_role(&admin, s, &Role::Member);
    }
    let asset = env.register_stellar_asset_contract_v2(admin.clone()).address();
    let vault = deploy_vault(&env, &admin, &asset, &svec(&env, &esigners), 2, &acl_id);
    let owner = soroban_sdk::Address::generate(&env);
    soroban_sdk::token::StellarAssetClient::new(&env, &asset).mint(&owner, &1_000_000);
    let lock = vault.lock_tokens(&owner, &5_000, &100_000, &symbol_short!("l"));
    vault.approve_emergency(&esigners[0], &lock);
    vault.approve_emergency(&esigners[1], &lock);
    vault.emergency_unlock(&esigners[0], &lock);
    assert_eq!(
        vault.try_emergency_unlock(&esigners[0], &lock),
        Err(Ok(vault::Error::AlreadyClaimed))
    );
}

/// INV-X4: A passed Funding proposal in governance drives a cross-contract
/// call to the treasury, creating a withdrawal transaction. The proposal is
/// only marked executed after the treasury accepts the request. Governance
/// must be registered as a treasury signer for the call to succeed.
#[test]
fn funding_proposal_execution_queues_treasury_withdrawal() {
    let env = new_env();
    let admin = soroban_sdk::Address::generate(&env);
    let (acl_id, _acl) = deploy_acl(&env, &admin);

    let gov_member = soroban_sdk::Address::generate(&env);
    _acl.assign_role(&admin, &gov_member, &Role::Member);

    let treasury_signers = addrs(&env, 2);
    for s in &treasury_signers {
        _acl.assign_role(&admin, s, &Role::Member);
    }

    let asset = env.register_stellar_asset_contract_v2(admin.clone()).address();
    let treasury = deploy_treasury(
        &env, &admin, &asset, 2,
        &svec(&env, &treasury_signers),
        &acl_id,
    );

    // Add governance as a treasury signer so it can propose withdrawals
    let gov_members = addrs(&env, 1);
    for m in &gov_members {
        _acl.assign_role(&admin, m, &Role::Member);
    }
    let gov = deploy_governance(
        &env, &admin, &svec(&env, &gov_members), 34, 50,
        &acl_id, &treasury.address,
    );
    treasury.add_signer(&admin, &gov.address);

    // Fund the treasury
    let sac_client = soroban_sdk::token::StellarAssetClient::new(&env, &asset);
    sac_client.mint(&treasury.address, &100_000);
    treasury.deposit(&treasury_signers[0], &100_000);

    // Create and pass a Funding proposal
    let recipient = soroban_sdk::Address::generate(&env);
    let pid = gov.create_proposal(
        &gov_members[0],
        &symbol_short!("fund_ops"),
        &symbol_short!("ops"),
        &ProposalAction::Funding,
        &40_000,
        &recipient,
    );
    gov.vote(&gov_members[0], &pid, &true);
    advance_seq(&env, 100);
    assert_eq!(gov.finalize(&gov_members[0], &pid), ProposalStatus::Passed);

    // Execute — should create a treasury withdrawal transaction
    gov.execute_proposal(&admin, &pid);
    let proposal = gov.get_proposal(&pid);
    assert_eq!(proposal.status, ProposalStatus::Executed);

    // Verify treasury transaction was created
    let tx = treasury.get_transaction(&1);
    assert_eq!(tx.amount, 40_000);
    assert_eq!(tx.to, recipient);
    assert_eq!(tx.proposer, gov.address);
    assert_eq!(tx.approvals.len(), 1);
    assert_eq!(tx.approvals.get(0).unwrap(), gov.address);
    assert_eq!(tx.executed, false);
    assert_eq!(tx.canceled, false);

    assert_treasury_invariants(&treasury, 100_000, 0);
    assert_acl_consistent(&_acl);
}

/// INV-X4 deny path: governance not registered as a treasury signer
/// cannot propose withdrawals — the Funding proposal stays un-executed
/// and the treasury is never touched.
#[test]
fn funding_proposal_fails_when_governance_not_a_signer() {
    let env = new_env();
    let admin = soroban_sdk::Address::generate(&env);
    let (acl_id, _acl) = deploy_acl(&env, &admin);

    let gov_member = soroban_sdk::Address::generate(&env);
    _acl.assign_role(&admin, &gov_member, &Role::Member);

    let treasury_signers = addrs(&env, 2);
    for s in &treasury_signers {
        _acl.assign_role(&admin, s, &Role::Member);
    }

    let asset = env.register_stellar_asset_contract_v2(admin.clone()).address();
    let treasury = deploy_treasury(
        &env, &admin, &asset, 2,
        &svec(&env, &treasury_signers),
        &acl_id,
    );

    // NOTE: governance is NOT added as a treasury signer
    let gov_members = addrs(&env, 1);
    for m in &gov_members {
        _acl.assign_role(&admin, m, &Role::Member);
    }
    let gov = deploy_governance(
        &env, &admin, &svec(&env, &gov_members), 34, 50,
        &acl_id, &treasury.address,
    );

    let sac_client = soroban_sdk::token::StellarAssetClient::new(&env, &asset);
    sac_client.mint(&treasury.address, &100_000);
    treasury.deposit(&treasury_signers[0], &100_000);

    let recipient = soroban_sdk::Address::generate(&env);
    let pid = gov.create_proposal(
        &gov_members[0],
        &symbol_short!("fund_ops"),
        &symbol_short!("ops"),
        &ProposalAction::Funding,
        &40_000,
        &recipient,
    );
    gov.vote(&gov_members[0], &pid, &true);
    advance_seq(&env, 100);
    assert_eq!(gov.finalize(&gov_members[0], &pid), ProposalStatus::Passed);

    // Execute should fail — governance is not a treasury signer
    assert_eq!(
        gov.try_execute_proposal(&admin, &pid),
        Err(Ok(governance::Error::ProposalRejected))
    );

    // Proposal must NOT be marked executed
    let proposal = gov.get_proposal(&pid);
    assert_eq!(proposal.status, ProposalStatus::Passed);

    // No treasury transaction should exist
    assert_eq!(
        treasury.try_get_transaction(&1),
        Err(Ok(treasury::Error::TransactionNotFound))
    );

    assert_acl_consistent(&_acl);
}

/// INV-X4 failure-atomicity: insufficient funds in the treasury must
/// not mark the governance proposal executed.
#[test]
fn funding_proposal_insufficient_treasury_balance_does_not_execute() {
    let env = new_env();
    let admin = soroban_sdk::Address::generate(&env);
    let (acl_id, _acl) = deploy_acl(&env, &admin);

    let gov_member = soroban_sdk::Address::generate(&env);
    _acl.assign_role(&admin, &gov_member, &Role::Member);

    let treasury_signers = addrs(&env, 2);
    for s in &treasury_signers {
        _acl.assign_role(&admin, s, &Role::Member);
    }

    let asset = env.register_stellar_asset_contract_v2(admin.clone()).address();
    let treasury = deploy_treasury(
        &env, &admin, &asset, 2,
        &svec(&env, &treasury_signers),
        &acl_id,
    );

    let gov_members = addrs(&env, 1);
    for m in &gov_members {
        _acl.assign_role(&admin, m, &Role::Member);
    }
    let gov = deploy_governance(
        &env, &admin, &svec(&env, &gov_members), 34, 50,
        &acl_id, &treasury.address,
    );
    treasury.add_signer(&admin, &gov.address);

    // Treasury has only 1_000, but proposal asks for 40_000
    let sac_client = soroban_sdk::token::StellarAssetClient::new(&env, &asset);
    sac_client.mint(&treasury.address, &1_000);
    treasury.deposit(&treasury_signers[0], &1_000);

    let recipient = soroban_sdk::Address::generate(&env);
    let pid = gov.create_proposal(
        &gov_members[0],
        &symbol_short!("fund_big"),
        &symbol_short!("big"),
        &ProposalAction::Funding,
        &40_000,
        &recipient,
    );
    gov.vote(&gov_members[0], &pid, &true);
    advance_seq(&env, 100);
    assert_eq!(gov.finalize(&gov_members[0], &pid), ProposalStatus::Passed);

    // Execute should fail — insufficient treasury balance
    assert_eq!(
        gov.try_execute_proposal(&admin, &pid),
        Err(Ok(governance::Error::ProposalRejected))
    );

    // Proposal MUST NOT be marked executed — failure atomicity
    let proposal = gov.get_proposal(&pid);
    assert_eq!(proposal.status, ProposalStatus::Passed);

    assert_treasury_invariants(&treasury, 1_000, 0);
    assert_acl_consistent(&_acl);
}
