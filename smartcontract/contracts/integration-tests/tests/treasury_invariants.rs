//! Treasury security invariants (INV-T1 .. INV-T6).

use soroban_sdk::testutils::Address as _;
mod common;

use common::*;
use soroban_sdk::symbol_short;

fn setup() -> (
    soroban_sdk::Env,
    soroban_sdk::Address,                 // admin
    std::vec::Vec<soroban_sdk::Address>,  // signers
    soroban_sdk::Address,                 // recipient
    TreasuryContractClient<'static>,
) {
    let env = new_env();
    let admin = soroban_sdk::Address::generate(&env);
    let (acl_id, _acl) = deploy_acl(&env, &admin);
    let signers = addrs(&env, 3);
    let asset = env.register_stellar_asset_contract_v2(admin.clone()).address();
    let recipient = soroban_sdk::Address::generate(&env);
    let c = deploy_treasury(&env, &admin, &asset, 2, &svec(&env, &signers), &acl_id);
    let token_admin = soroban_sdk::token::StellarAssetClient::new(&env, &asset);
    for s in &signers {
        token_admin.mint(s, &10_000_000);
    }
    token_admin.mint(&admin, &10_000_000);
    (env, admin, signers, recipient, c)
}

/// Deterministic, replayable operation sequences. Expected balance is tracked by
/// the harness and checked against contract state after every step (INV-T1/T2/T5).
#[test]
fn seeded_operation_sequences() {
    for seed in [1u64, 7, 42, 99, 12345] {
        let (env, admin, signers, recipient, c) = setup();
        let memo = symbol_short!("w");
        let mut rng = Rng::new(seed);
        let mut deposited = 0i128;
        let mut withdrawn = 0i128;
        let mut last_tx = 0u64;

        for _ in 0..40 {
            match rng.below(5) {
                0 => {
                    let s = &signers[rng.below(signers.len() as u64) as usize];
                    let amt = (rng.below(9) + 1) as i128 * 1_000;
                    if c.try_deposit(s, &amt).is_ok() {
                        deposited += amt;
                    }
                }
                1 => {
                    let amt = (rng.below(5) + 1) as i128 * 1_000;
                    let exp = env.ledger().timestamp() + 10_000;
                    if let Ok(Ok(id)) =
                        c.try_propose_withdrawal(&signers[0], &recipient, &amt, &memo, &exp)
                    {
                        last_tx = id;
                    }
                }
                2 => {
                    let _ = c.try_approve(&signers[1], &last_tx);
                }
                3 => {
                    if last_tx != 0 {
                        if let Ok(Ok(tx)) = c.try_get_transaction(&last_tx) {
                            if c.try_execute(&signers[0], &last_tx).is_ok() {
                                withdrawn += tx.amount;
                            }
                        }
                    }
                }
                _ => {
                    let cfg = c.get_config();
                    let nt = (rng.below(cfg.signer_count as u64) + 1) as u32;
                    let _ = c.try_set_threshold(&admin, &nt);
                }
            }
            assert_treasury_invariants(&c, deposited, withdrawn);
        }
    }
}

/// INV-T3: an executed proposal can never settle twice.
#[test]
fn no_double_execution() {
    let (env, _admin, signers, recipient, c) = setup();
    c.deposit(&signers[0], &10_000);
    let exp = env.ledger().timestamp() + 10_000;
    let id = c.propose_withdrawal(&signers[0], &recipient, &4_000, &symbol_short!("rent"), &exp);
    c.approve(&signers[1], &id); // proposer + this = threshold 2

    c.execute(&signers[0], &id);
    assert_eq!(c.get_balance(), 6_000);

    // Replay is rejected and the balance is unchanged.
    assert_eq!(
        c.try_execute(&signers[0], &id),
        Err(Ok(treasury::Error::AlreadyExecuted))
    );
    assert_eq!(c.get_balance(), 6_000);
}

/// INV-T4: an expired proposal cannot be executed.
#[test]
fn expired_cannot_execute() {
    let (env, _admin, signers, recipient, c) = setup();
    c.deposit(&signers[0], &10_000);
    let exp = env.ledger().timestamp() + 100;
    let id = c.propose_withdrawal(&signers[0], &recipient, &4_000, &symbol_short!("rent"), &exp);
    c.approve(&signers[1], &id);

    advance_time(&env, 200); // past expiry

    assert_eq!(
        c.try_execute(&signers[0], &id),
        Err(Ok(treasury::Error::TransactionExpired))
    );
    assert_eq!(c.get_balance(), 10_000);
}

/// INV-T4: a policy change (signer/threshold churn) invalidates stale proposals so
/// no stale-policy approval can authorize execution.
#[test]
fn policy_change_invalidates_stale_proposal() {
    let (env, admin, signers, recipient, c) = setup();
    c.deposit(&signers[0], &10_000);
    let exp = env.ledger().timestamp() + 10_000;
    let id = c.propose_withdrawal(&signers[0], &recipient, &4_000, &symbol_short!("rent"), &exp);

    // Churn the signer set -> bumps policy version.
    let new_signer = soroban_sdk::Address::generate(&env);
    c.add_signer(&admin, &new_signer);

    // Approval and execution against the stale policy are both rejected.
    assert_eq!(
        c.try_approve(&signers[1], &id),
        Err(Ok(treasury::Error::PolicyInvalidated))
    );
    assert_eq!(
        c.try_execute(&signers[0], &id),
        Err(Ok(treasury::Error::PolicyInvalidated))
    );
    assert_eq!(c.get_balance(), 10_000);
}

/// INV-T6: a failed call preserves pre-call state.
#[test]
fn insufficient_funds_preserves_state() {
    let (env, _admin, signers, recipient, c) = setup();
    c.deposit(&signers[0], &1_000);
    let exp = env.ledger().timestamp() + 10_000;

    // Proposing more than the balance fails and leaves the balance intact.
    assert_eq!(
        c.try_propose_withdrawal(&signers[0], &recipient, &5_000, &symbol_short!("x"), &exp),
        Err(Ok(treasury::Error::InsufficientFunds))
    );
    assert_eq!(c.get_balance(), 1_000);
    assert_eq!(c.get_config().tx_count, 0);
}

/// INV-T5: the threshold can never exceed the signer count.
#[test]
fn threshold_bounds_enforced() {
    let (_env, admin, _signers, _recipient, c) = setup();
    assert_eq!(
        c.try_set_threshold(&admin, &9),
        Err(Ok(treasury::Error::InvalidThreshold))
    );
    let cfg = c.get_config();
    assert!(cfg.threshold >= 1 && cfg.threshold <= cfg.signer_count);
}
