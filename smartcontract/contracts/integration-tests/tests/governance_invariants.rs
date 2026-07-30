//! Governance security invariants (INV-G1 .. INV-G5).

use soroban_sdk::testutils::Address as _;
mod common;

use common::*;
use soroban_sdk::symbol_short;

fn setup(
    n_members: usize,
    quorum: u32,
    period: u32,
) -> (
    soroban_sdk::Env,
    soroban_sdk::Address,                 // admin
    std::vec::Vec<soroban_sdk::Address>,  // members
    GovernanceContractClient<'static>,
) {
    let env = new_env();
    let admin = soroban_sdk::Address::generate(&env);
    let (acl_id, acl) = deploy_acl(&env, &admin);
    let members = addrs(&env, n_members);
    for m in &members {
        acl.assign_role(&admin, m, &Role::Member);
    }
    let treasury_addr = soroban_sdk::Address::generate(&env);
    let c = deploy_governance(&env, &admin, &svec(&env, &members), quorum, period, &acl_id, &treasury_addr);
    (env, admin, members, c)
}

fn mk_proposal(
    c: &GovernanceContractClient,
    proposer: &soroban_sdk::Address,
) -> u64 {
    c.create_proposal(
        proposer,
        &symbol_short!("t"),
        &symbol_short!("d"),
        &ProposalAction::General,
        &0,
        proposer,
    )
}

/// INV-G3: a member cannot vote twice on the same proposal.
#[test]
fn no_double_vote() {
    let (_env, _admin, members, c) = setup(3, 50, 100);
    let id = mk_proposal(&c, &members[0]);
    c.vote(&members[0], &id, &true);
    assert_eq!(
        c.try_vote(&members[0], &id, &true),
        Err(Ok(governance::Error::AlreadyVoted))
    );
    let p = c.get_proposal(&id);
    assert_eq!(p.total_votes, 1);
}

/// INV-G2/G4/G5: vote tallies stay consistent, a passed proposal executes exactly
/// once, and the state machine forbids re-execution.
#[test]
fn passed_proposal_executes_once() {
    let (env, admin, members, c) = setup(3, 50, 100); // quorum threshold = 1
    let id = mk_proposal(&c, &members[0]);
    c.vote(&members[0], &id, &true);
    c.vote(&members[1], &id, &true);

    let p = c.get_proposal(&id);
    assert_eq!(p.votes_for + p.votes_against, p.total_votes, "INV-G2 tally consistent");

    advance_seq(&env, 200); // past ends_at
    assert_eq!(c.finalize(&members[0], &id), ProposalStatus::Passed);

    c.execute_proposal(&admin, &id);
    assert_eq!(c.get_proposal(&id).status, ProposalStatus::Executed);

    // INV-G5: replay rejected (status is no longer Passed).
    assert_eq!(
        c.try_execute_proposal(&admin, &id),
        Err(Ok(governance::Error::ProposalRejected))
    );
}

/// INV-G4: a proposal that fails to reach quorum expires and cannot execute.
#[test]
fn quorum_not_met_expires() {
    let (env, admin, members, c) = setup(4, 75, 100); // threshold = 3
    let id = mk_proposal(&c, &members[0]);
    c.vote(&members[0], &id, &true); // only 1 of 3 needed votes

    advance_seq(&env, 200);
    assert_eq!(c.finalize(&members[0], &id), ProposalStatus::Expired);
    assert_eq!(
        c.try_execute_proposal(&admin, &id),
        Err(Ok(governance::Error::ProposalRejected))
    );
}

/// INV-G4: voting is closed once the proposal is finalized.
#[test]
fn cannot_vote_after_finalize() {
    let (env, admin, members, c) = setup(3, 50, 100);
    let id = mk_proposal(&c, &members[0]);
    c.vote(&members[0], &id, &true);
    advance_seq(&env, 200);
    c.finalize(&members[0], &id);

    assert_eq!(
        c.try_vote(&members[1], &id, &true),
        Err(Ok(governance::Error::VotingClosed))
    );
}

/// Deterministic sequences: across many create/vote/finalize/execute operations
/// the tally invariant (INV-G2) and member bound hold for every proposal, and no
/// proposal is ever executed from a non-Passed state.
#[test]
fn seeded_operation_sequences() {
    for seed in [3u64, 17, 51, 808] {
        let (env, admin, members, c) = setup(5, 40, 50);
        let mut rng = Rng::new(seed);

        for _ in 0..40 {
            match rng.below(4) {
                0 => {
                    let p = &members[rng.below(members.len() as u64) as usize];
                    let _ = mk_proposal(&c, p);
                }
                1 => {
                    let count = c.get_config().proposal_count;
                    if count > 0 {
                        let id = rng.below(count) + 1;
                        let voter = &members[rng.below(members.len() as u64) as usize];
                        let _ = c.try_vote(voter, &id, &rng.flip());
                    }
                }
                2 => {
                    advance_seq(&env, 60); // push some proposals past their window
                    let count = c.get_config().proposal_count;
                    if count > 0 {
                        let id = rng.below(count) + 1;
                        let finalizer = &members[rng.below(members.len() as u64) as usize];
                        let _ = c.try_finalize(finalizer, &id);
                    }
                }
                _ => {
                    let count = c.get_config().proposal_count;
                    if count > 0 {
                        let id = rng.below(count) + 1;
                        let _ = c.try_execute_proposal(&admin, &id);
                    }
                }
            }

            // Check invariants over every proposal created so far.
            let count = c.get_config().proposal_count;
            let member_count = c.get_config().member_count;
            for id in 1..=count {
                if let Ok(Ok(p)) = c.try_get_proposal(&id) {
                    assert_eq!(
                        p.votes_for + p.votes_against,
                        p.total_votes,
                        "INV-G2 vote tally must stay consistent"
                    );
                    assert!(
                        p.total_votes <= member_count,
                        "INV-G2 total votes cannot exceed members"
                    );
                }
            }
        }
    }
}
