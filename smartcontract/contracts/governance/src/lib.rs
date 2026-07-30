#![no_std]

#[cfg(any(test, feature = "testutils"))]
extern crate std;

use soroban_sdk::{
    contract, contractimpl, contracttype, contracterror, symbol_short,
    Address, Env, Symbol, Vec,
    log,
};

use stellar_sentinel_access_control::AccessControlContractClient;
use stellar_sentinel_treasury::TreasuryContractClient;

// ============================================================================
// Error Codes
// ============================================================================

/// Contract error codes for the Governance module.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// Contract has not been initialized.
    NotInitialized = 1,
    /// Contract is already initialized.
    AlreadyInitialized = 2,
    /// Caller does not have permission.
    Unauthorized = 3,
    /// Proposal was not found.
    ProposalNotFound = 4,
    /// Voter has already voted on this proposal.
    AlreadyVoted = 5,
    /// Voting period has closed for this proposal.
    VotingClosed = 6,
    /// Proposal has already been executed.
    AlreadyExecuted = 7,
    /// Quorum has not been reached.
    QuorumNotMet = 8,
    /// Proposal did not pass (more nay than yea).
    ProposalRejected = 9,
    /// Invalid proposal parameters.
    InvalidProposal = 10,
    /// Voter is not a registered member.
    NotAMember = 11,
    /// Voting period is still active.
    VotingStillActive = 12,
}

// ============================================================================
// Storage Types
// ============================================================================

/// Storage keys for the governance contract.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    /// Admin address.
    Admin,
    /// Whether contract is initialized.
    Initialized,
    /// List of DAO members who can vote.
    Members,
    /// Minimum percentage of votes required for quorum (0-100).
    QuorumPercent,
    /// Duration of voting period in ledger sequence numbers.
    VotingPeriod,
    /// Counter for proposal IDs.
    ProposalCounter,
    /// A proposal by its ID.
    Proposal(u64),
    /// Record of a vote: (proposal_id, voter_address).
    Vote(u64, Address),
    /// The access-control contract address for RBAC enforcement.
    AclAddress,
    /// The treasury contract address for cross-contract fund execution.
    TreasuryAddress,
}

/// The type of action a proposal requests.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposalAction {
    /// Request funds from the treasury.
    Funding,
    /// Change a governance parameter.
    PolicyChange,
    /// Add a new member to the DAO.
    AddMember,
    /// Remove a member from the DAO.
    RemoveMember,
    /// A general-purpose proposal.
    General,
}

/// The current status of a proposal.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposalStatus {
    /// Proposal is active and accepting votes.
    Active,
    /// Proposal passed and is awaiting execution.
    Passed,
    /// Proposal was rejected.
    Rejected,
    /// Proposal was executed.
    Executed,
    /// Proposal expired without reaching quorum.
    Expired,
}

/// A governance proposal.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proposal {
    /// Unique identifier.
    pub id: u64,
    /// Title of the proposal.
    pub title: Symbol,
    /// Short description.
    pub description: Symbol,
    /// The type of action being proposed.
    pub action: ProposalAction,
    /// Address of the proposer.
    pub proposer: Address,
    /// Number of votes in favor.
    pub votes_for: u32,
    /// Number of votes against.
    pub votes_against: u32,
    /// Total number of votes cast.
    pub total_votes: u32,
    /// Current status.
    pub status: ProposalStatus,
    /// Ledger sequence when voting opened.
    pub created_at: u32,
    /// Ledger sequence when voting closes.
    pub ends_at: u32,
    /// Optional: amount requested (for funding proposals).
    pub amount: i128,
    /// Optional: target address (for member add/remove).
    pub target: Address,
}

/// Governance configuration.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovConfig {
    pub admin: Address,
    pub member_count: u32,
    pub quorum_percent: u32,
    pub voting_period: u32,
    pub proposal_count: u64,
}

// ============================================================================
// Contract Implementation
// ============================================================================

#[contract]
pub struct GovernanceContract;

#[contractimpl]
impl GovernanceContract {
    // ========================================================================
    // Initialization
    // ========================================================================

    /// Initialize the governance contract.
    ///
    /// # Arguments
    /// * `admin` - The admin address.
    /// * `members` - Initial list of DAO members.
    /// * `quorum_percent` - Minimum vote percentage for quorum (1-100).
    /// * `voting_period` - Duration of voting in ledger sequences.
    /// * `acl_address` - The access-control contract address for RBAC enforcement.
    /// * `treasury_address` - The treasury contract address for cross-contract fund execution.
    pub fn initialize(
        env: Env,
        admin: Address,
        members: Vec<Address>,
        quorum_percent: u32,
        voting_period: u32,
        acl_address: Address,
        treasury_address: Address,
    ) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Initialized) {
            return Err(Error::AlreadyInitialized);
        }

        let acl_client = AccessControlContractClient::new(&env, &acl_address);
        if !acl_client.is_admin_or_above(&admin) {
            return Err(Error::Unauthorized);
        }

        admin.require_auth();

        env.storage().instance().set(&DataKey::Initialized, &true);
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Members, &members);
        env.storage()
            .instance()
            .set(&DataKey::QuorumPercent, &quorum_percent);
        env.storage()
            .instance()
            .set(&DataKey::VotingPeriod, &voting_period);
        env.storage()
            .instance()
            .set(&DataKey::ProposalCounter, &0_u64);
        env.storage().instance().set(&DataKey::AclAddress, &acl_address);
        env.storage().instance().set(&DataKey::TreasuryAddress, &treasury_address);

        env.events().publish(
            (symbol_short!("gov"), symbol_short!("init")),
            (admin.clone(), members.len(), quorum_percent),
        );

        log!(&env, "Governance initialized: {} members, {}% quorum", members.len(), quorum_percent);
        Ok(())
    }

    // ========================================================================
    // Proposal Creation
    // ========================================================================

    /// Create a new governance proposal.
    ///
    /// # Arguments
    /// * `proposer` - Must be a DAO member.
    /// * `title` - Short title for the proposal.
    /// * `description` - Description of what the proposal does.
    /// * `action` - The type of proposal action.
    /// * `amount` - Amount requested (relevant for Funding proposals, 0 otherwise).
    /// * `target` - Target address (relevant for AddMember/RemoveMember, use proposer otherwise).
    pub fn create_proposal(
        env: Env,
        proposer: Address,
        title: Symbol,
        description: Symbol,
        action: ProposalAction,
        amount: i128,
        target: Address,
    ) -> Result<u64, Error> {
        Self::require_initialized(&env)?;
        Self::require_member(&env, &proposer)?;

        proposer.require_auth();

        // Get and increment counter
        let proposal_id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::ProposalCounter)
            .unwrap_or(0)
            + 1;
        env.storage()
            .instance()
            .set(&DataKey::ProposalCounter, &proposal_id);

        // Calculate voting end
        let voting_period: u32 = env
            .storage()
            .instance()
            .get(&DataKey::VotingPeriod)
            .unwrap_or(1000);
        let current_ledger = env.ledger().sequence();
        let ends_at = current_ledger + voting_period;

        let proposal = Proposal {
            id: proposal_id,
            title: title.clone(),
            description,
            action: action.clone(),
            proposer: proposer.clone(),
            votes_for: 0,
            votes_against: 0,
            total_votes: 0,
            status: ProposalStatus::Active,
            created_at: current_ledger,
            ends_at,
            amount,
            target: target.clone(),
        };

        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);

        env.events().publish(
            (symbol_short!("gov"), symbol_short!("propose")),
            (proposal_id, proposer.clone(), title, action),
        );

        log!(&env, "Proposal #{} created by {:?}", proposal_id, proposer);
        Ok(proposal_id)
    }

    // ========================================================================
    // Voting
    // ========================================================================

    /// Cast a vote on an active proposal.
    ///
    /// # Arguments
    /// * `voter` - Must be a DAO member.
    /// * `proposal_id` - The ID of the proposal to vote on.
    /// * `vote_for` - `true` to vote in favor, `false` to vote against.
    pub fn vote(
        env: Env,
        voter: Address,
        proposal_id: u64,
        vote_for: bool,
    ) -> Result<(), Error> {
        Self::require_initialized(&env)?;
        Self::require_member(&env, &voter)?;

        voter.require_auth();

        // Check if already voted
        let vote_key = DataKey::Vote(proposal_id, voter.clone());
        if env.storage().persistent().has(&vote_key) {
            return Err(Error::AlreadyVoted);
        }

        // Load proposal
        let mut proposal: Proposal = env
            .storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .ok_or(Error::ProposalNotFound)?;

        // Check proposal is still active
        if proposal.status != ProposalStatus::Active {
            return Err(Error::VotingClosed);
        }

        // Check voting period hasn't ended
        let current_ledger = env.ledger().sequence();
        if current_ledger > proposal.ends_at {
            return Err(Error::VotingClosed);
        }

        // Record vote
        if vote_for {
            proposal.votes_for += 1;
        } else {
            proposal.votes_against += 1;
        }
        proposal.total_votes += 1;

        // Save vote record (prevents double voting)
        env.storage().persistent().set(&vote_key, &vote_for);

        // Save updated proposal
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);

        env.events().publish(
            (symbol_short!("gov"), symbol_short!("vote")),
            (proposal_id, voter.clone(), vote_for),
        );

        log!(
            &env,
            "Vote cast on proposal #{}: {:?} voted {}",
            proposal_id,
            voter,
            if vote_for { "FOR" } else { "AGAINST" }
        );

        Ok(())
    }

    // ========================================================================
    // Proposal Finalization
    // ========================================================================

    /// Finalize a proposal after the voting period ends.
    /// Determines if the proposal passed or was rejected based on votes and quorum.
    pub fn finalize(env: Env, caller: Address, proposal_id: u64) -> Result<ProposalStatus, Error> {
        Self::require_initialized(&env)?;
        Self::require_member(&env, &caller)?;

        caller.require_auth();

        let mut proposal: Proposal = env
            .storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .ok_or(Error::ProposalNotFound)?;

        if proposal.status != ProposalStatus::Active {
            return Err(Error::VotingClosed);
        }

        // Check voting period has ended
        let current_ledger = env.ledger().sequence();
        if current_ledger <= proposal.ends_at {
            return Err(Error::VotingStillActive);
        }

        // Check quorum
        let members: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Members)
            .unwrap_or(Vec::new(&env));
        let quorum_percent: u32 = env
            .storage()
            .instance()
            .get(&DataKey::QuorumPercent)
            .unwrap_or(50);

        let quorum_threshold = (members.len() * quorum_percent) / 100;
        if proposal.total_votes < quorum_threshold {
            proposal.status = ProposalStatus::Expired;
        } else if proposal.votes_for > proposal.votes_against {
            proposal.status = ProposalStatus::Passed;
        } else {
            proposal.status = ProposalStatus::Rejected;
        }

        let final_status = proposal.status.clone();

        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);

        env.events().publish(
            (symbol_short!("gov"), symbol_short!("finalize")),
            (proposal_id, final_status.clone()),
        );

        Ok(final_status)
    }

    /// Execute a passed proposal.
    /// Only the admin or proposer can execute.
    ///
    /// # Cross-contract execution (Funding proposals)
    ///
    /// For `ProposalAction::Funding`, the governance contract calls the
    /// treasury's `propose_withdrawal()` to queue a withdrawal for the
    /// approved amount and recipient. This follows the *propose-into-treasury*
    /// trust model: governance does not directly execute the withdrawal;
    /// instead it creates a treasury transaction that still requires
    /// signer approvals according to the treasury's m-of-n policy.
    ///
    /// The governance contract must be registered as a signer in the treasury
    /// (via `TreasuryContract::add_signer`) for the cross-contract call to
    /// succeed. If the treasury call fails (e.g. insufficient funds, governance
    /// not a signer, policy invalidated), the proposal is NOT marked executed
    /// and the error is propagated to the caller.
    ///
    /// This preserves treasury sovereignty — the governance DAO can approve
    /// spending but cannot unilaterally move funds without going through the
    /// treasury's own multi-sig approval process.
    pub fn execute_proposal(
        env: Env,
        executor: Address,
        proposal_id: u64,
    ) -> Result<(), Error> {
        Self::require_initialized(&env)?;

        executor.require_auth();

        let mut proposal: Proposal = env
            .storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .ok_or(Error::ProposalNotFound)?;

        if proposal.status != ProposalStatus::Passed {
            return Err(Error::ProposalRejected);
        }

        // Only admin or proposer can execute
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        if executor != proposal.proposer && executor != admin {
            return Err(Error::Unauthorized);
        }

        if executor == admin {
            Self::require_acl_admin_or_above(&env, &executor)?;
        } else if executor == proposal.proposer {
            Self::require_acl_member_or_above(&env, &executor)?;
        }

        // Handle member add/remove actions
        match proposal.action {
            ProposalAction::AddMember => {
                Self::internal_add_member(&env, &proposal.target)?;
            }
            ProposalAction::RemoveMember => {
                Self::internal_remove_member(&env, &proposal.target)?;
            }
            ProposalAction::Funding => {
                let treasury_address: Address = env
                    .storage()
                    .instance()
                    .get(&DataKey::TreasuryAddress)
                    .ok_or(Error::NotInitialized)?;

                let treasury_client =
                    TreasuryContractClient::new(&env, &treasury_address);

                let expires_at = env
                    .ledger()
                    .timestamp()
                    .checked_add(7 * 24 * 3600)
                    .unwrap_or(u64::MAX);

                let memo = symbol_short!("gov_fund");

                let _ = treasury_client
                    .try_propose_withdrawal(
                        &env.current_contract_address(),
                        &proposal.target,
                        &proposal.amount,
                        &memo,
                        &expires_at,
                    )
                    .map_err(|_| Error::ProposalRejected)?;
            }
            ProposalAction::PolicyChange | ProposalAction::General => {
                // PolicyChange and General proposals are handled externally
            }
        }

        proposal.status = ProposalStatus::Executed;
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);

        env.events().publish(
            (symbol_short!("gov"), symbol_short!("exec")),
            (proposal_id, executor.clone()),
        );

        Ok(())
    }

    // ========================================================================
    // Member Management (Internal)
    // ========================================================================

    fn internal_add_member(env: &Env, member: &Address) -> Result<(), Error> {
        let mut members: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Members)
            .unwrap_or(Vec::new(env));

        // Check not already a member
        for i in 0..members.len() {
            if members.get(i).unwrap() == *member {
                return Ok(()); // Already a member, no-op
            }
        }

        members.push_back(member.clone());
        env.storage().instance().set(&DataKey::Members, &members);
        Ok(())
    }

    fn internal_remove_member(env: &Env, member: &Address) -> Result<(), Error> {
        let members: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Members)
            .unwrap_or(Vec::new(env));

        let mut new_members = Vec::new(env);
        for i in 0..members.len() {
            let m = members.get(i).unwrap();
            if m != *member {
                new_members.push_back(m);
            }
        }

        env.storage()
            .instance()
            .set(&DataKey::Members, &new_members);
        Ok(())
    }

    // ========================================================================
    // Query Functions
    // ========================================================================

    /// Get a proposal by its ID.
    pub fn get_proposal(env: Env, proposal_id: u64) -> Result<Proposal, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .ok_or(Error::ProposalNotFound)
    }

    /// Get governance configuration.
    pub fn get_config(env: Env) -> Result<GovConfig, Error> {
        Self::require_initialized(&env)?;

        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        let members: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Members)
            .unwrap_or(Vec::new(&env));
        let quorum_percent: u32 = env
            .storage()
            .instance()
            .get(&DataKey::QuorumPercent)
            .unwrap_or(50);
        let voting_period: u32 = env
            .storage()
            .instance()
            .get(&DataKey::VotingPeriod)
            .unwrap_or(1000);
        let proposal_count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::ProposalCounter)
            .unwrap_or(0);

        Ok(GovConfig {
            admin,
            member_count: members.len(),
            quorum_percent,
            voting_period,
            proposal_count,
        })
    }

    /// Get the list of DAO members.
    pub fn get_members(env: Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get(&DataKey::Members)
            .unwrap_or(Vec::new(&env))
    }

    /// Check if an address has voted on a proposal.
    pub fn has_voted(env: Env, proposal_id: u64, voter: Address) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::Vote(proposal_id, voter))
    }

    // ========================================================================
    // Admin Functions
    // ========================================================================

    /// Transfer admin role to a new address.
    pub fn transfer_admin(
        env: Env,
        current_admin: Address,
        new_admin: Address,
    ) -> Result<(), Error> {
        Self::require_initialized(&env)?;
        Self::require_admin(&env, &current_admin)?;

        current_admin.require_auth();

        Self::require_acl_admin_or_above(&env, &new_admin)?;

        env.storage()
            .instance()
            .set(&DataKey::Admin, &new_admin);

        env.events().publish(
            (symbol_short!("gov"), symbol_short!("admin")),
            (current_admin, new_admin.clone()),
        );

        Ok(())
    }

    /// Update the quorum percentage. Admin only.
    pub fn set_quorum(env: Env, admin: Address, new_quorum: u32) -> Result<(), Error> {
        Self::require_initialized(&env)?;
        Self::require_admin(&env, &admin)?;

        admin.require_auth();

        env.storage()
            .instance()
            .set(&DataKey::QuorumPercent, &new_quorum);

        env.events().publish(
            (symbol_short!("gov"), symbol_short!("quorum")),
            new_quorum,
        );

        Ok(())
    }

    /// Upgrade contract WASM. Admin only.
    pub fn upgrade(
        env: Env,
        admin: Address,
        new_wasm_hash: soroban_sdk::BytesN<32>,
    ) -> Result<(), Error> {
        Self::require_initialized(&env)?;
        Self::require_admin(&env, &admin)?;

        admin.require_auth();

        env.deployer().update_current_contract_wasm(new_wasm_hash);
        Ok(())
    }

    // ========================================================================
    // Internal Helpers
    // ========================================================================

    fn require_initialized(env: &Env) -> Result<(), Error> {
        if !env.storage().instance().has(&DataKey::Initialized) {
            return Err(Error::NotInitialized);
        }
        Ok(())
    }

    fn get_acl(env: &Env) -> Result<AccessControlContractClient, Error> {
        let acl_address: Address = env
            .storage()
            .instance()
            .get(&DataKey::AclAddress)
            .ok_or(Error::NotInitialized)?;
        Ok(AccessControlContractClient::new(env, &acl_address))
    }

    fn require_acl_admin_or_above(env: &Env, caller: &Address) -> Result<(), Error> {
        let acl = Self::get_acl(env)?;
        if !acl.is_admin_or_above(caller) {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    fn require_acl_member_or_above(env: &Env, caller: &Address) -> Result<(), Error> {
        let acl = Self::get_acl(env)?;
        if !acl.is_member_or_above(caller) {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    fn require_member(env: &Env, caller: &Address) -> Result<(), Error> {
        let members: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Members)
            .unwrap_or(Vec::new(env));

        let mut is_member = false;
        for i in 0..members.len() {
            if members.get(i).unwrap() == *caller {
                is_member = true;
                break;
            }
        }
        if !is_member {
            return Err(Error::NotAMember);
        }
        Self::require_acl_member_or_above(env, caller)
    }

    fn require_admin(env: &Env, caller: &Address) -> Result<(), Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        if *caller != admin {
            return Err(Error::Unauthorized);
        }
        Self::require_acl_admin_or_above(env, caller)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::Env;
    use stellar_sentinel_access_control::{
        AccessControlContract, AccessControlContractClient, Role,
    };

    fn deploy_acl(env: &Env, owner: &Address) -> Address {
        let acl_id = env.register_contract(None, AccessControlContract);
        let acl_client = AccessControlContractClient::new(env, &acl_id);
        acl_client.initialize(owner);
        acl_id
    }

    fn assign_role(env: &Env, acl_id: &Address, admin: &Address, target: &Address, role: &Role) {
        let acl_client = AccessControlContractClient::new(env, acl_id);
        acl_client.assign_role(admin, target, role);
    }

    fn setup_contract() -> (Env, Address, Address, Address, GovernanceContractClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, GovernanceContract);
        let client = GovernanceContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let acl_id = deploy_acl(&env, &admin);
        let treasury_id = Address::generate(&env);
        (env, admin, acl_id, treasury_id, client)
    }

    #[test]
    fn test_initialize() {
        let (env, admin, acl_id, treasury_id, client) = setup_contract();

        let member1 = Address::generate(&env);
        let member2 = Address::generate(&env);
        let members = Vec::from_array(&env, [member1.clone(), member2.clone()]);

        client.initialize(&admin, &members, &50, &1000, &acl_id, &treasury_id);

        let config = client.get_config();
        assert_eq!(config.admin, admin);
        assert_eq!(config.member_count, 2);
        assert_eq!(config.quorum_percent, 50);
        assert_eq!(config.voting_period, 1000);
    }

    #[test]
    fn test_create_proposal_and_vote() {
        let (env, admin, acl_id, treasury_id, client) = setup_contract();

        let member1 = Address::generate(&env);
        let member2 = Address::generate(&env);
        let member3 = Address::generate(&env);
        let members = Vec::from_array(
            &env,
            [member1.clone(), member2.clone(), member3.clone()],
        );

        assign_role(&env, &acl_id, &admin, &member1, &Role::Member);
        assign_role(&env, &acl_id, &admin, &member2, &Role::Member);
        assign_role(&env, &acl_id, &admin, &member3, &Role::Member);

        client.initialize(&admin, &members, &50, &1000, &acl_id, &treasury_id);

        // Create a funding proposal
        let proposal_id = client.create_proposal(
            &member1,
            &symbol_short!("fund_dev"),
            &symbol_short!("dev_work"),
            &ProposalAction::Funding,
            &500_000,
            &member1,
        );
        assert_eq!(proposal_id, 1);

        // Vote
        client.vote(&member1, &proposal_id, &true);
        client.vote(&member2, &proposal_id, &true);

        let proposal = client.get_proposal(&proposal_id);
        assert_eq!(proposal.votes_for, 2);
        assert_eq!(proposal.total_votes, 2);
        assert_eq!(proposal.status, ProposalStatus::Active);
    }

    #[test]
    fn test_has_voted() {
        let (env, admin, acl_id, treasury_id, client) = setup_contract();

        let member1 = Address::generate(&env);
        let members = Vec::from_array(&env, [member1.clone()]);

        assign_role(&env, &acl_id, &admin, &member1, &Role::Member);

        client.initialize(&admin, &members, &50, &1000, &acl_id, &treasury_id);

        let proposal_id = client.create_proposal(
            &member1,
            &symbol_short!("test"),
            &symbol_short!("test"),
            &ProposalAction::General,
            &0,
            &member1,
        );

        assert_eq!(client.has_voted(&proposal_id, &member1), false);

        client.vote(&member1, &proposal_id, &true);

        assert_eq!(client.has_voted(&proposal_id, &member1), true);
    }
}
