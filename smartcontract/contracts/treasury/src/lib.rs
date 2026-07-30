#![no_std]

#[cfg(any(test, feature = "testutils"))]
extern crate std;

use soroban_sdk::{
    contract, contractimpl, contracttype, contracterror, symbol_short,
    token,
    Address, Env, Symbol, Vec,
    log,
};

use stellar_sentinel_access_control::AccessControlContractClient;

// ============================================================================
// Error Codes
// ============================================================================

/// Contract error codes for the Treasury module.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// Contract has not been initialized yet.
    NotInitialized = 1,
    /// Contract is already initialized.
    AlreadyInitialized = 2,
    /// Caller is not authorized for this operation.
    Unauthorized = 3,
    /// Deposit amount must be greater than zero.
    InvalidAmount = 4,
    /// Treasury does not have enough funds to process withdrawal.
    InsufficientFunds = 5,
    /// The provided threshold is invalid (must be > 0 and <= signer count).
    InvalidThreshold = 6,
    /// Transaction proposal was not found.
    TransactionNotFound = 7,
    /// Signer has already approved this transaction.
    AlreadyApproved = 8,
    /// Transaction has already been executed.
    AlreadyExecuted = 9,
    /// Address is already a signer.
    AlreadySigner = 10,
    /// Address is not a signer.
    NotASigner = 11,
    /// Cannot remove signer — would breach threshold.
    ThresholdBreach = 12,
    /// Transaction has expired.
    TransactionExpired = 13,
    /// Transaction has been canceled.
    TransactionCanceled = 14,
    /// Caller is not the proposer.
    NotProposer = 15,
    /// Signer has not approved this transaction.
    NotApproved = 16,
    /// Expiry timestamp is invalid.
    InvalidExpiry = 17,
    /// Transaction policy has been invalidated.
    PolicyInvalidated = 18,
    /// Duplicate signer in initialization or addition.
    DuplicateSigner = 19,
}

// ============================================================================
// Storage Types
// ============================================================================

/// Keys for contract storage.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    /// The admin address that initialized the contract.
    Admin,
    /// The immutable asset address bound to this treasury.
    Asset,
    /// The approval threshold for multi-sig.
    Threshold,
    /// List of authorized signers.
    Signers,
    /// Native balance held in treasury.
    Balance,
    /// Transaction proposal by ID.
    Transaction(u64),
    /// Counter for transaction IDs.
    TxCounter,
    /// Whether the contract is initialized.
    Initialized,
    /// The current policy version for multi-sig.
    PolicyVersion,
    /// The access-control contract address for RBAC enforcement.
    AclAddress,
}

/// A pending transaction proposal in the multi-sig treasury.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transaction {
    /// Unique identifier.
    pub id: u64,
    /// Destination address for the withdrawal.
    pub to: Address,
    /// Amount to withdraw (in stroops).
    pub amount: i128,
    /// Text description / memo for the transaction.
    pub memo: Symbol,
    /// Addresses that have approved this transaction.
    pub approvals: Vec<Address>,
    /// Whether the transaction has been executed.
    pub executed: bool,
    /// Timestamp when the transaction was proposed.
    pub created_at: u64,
    /// Address that proposed the transaction.
    pub proposer: Address,
    /// Timestamp when the transaction expires.
    pub expires_at: u64,
    /// Whether the transaction has been canceled.
    pub canceled: bool,
    /// The policy version under which this transaction is valid.
    pub policy_version: u32,
}

/// Treasury configuration data.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreasuryConfig {
    /// Admin address.
    pub admin: Address,
    /// Asset address.
    pub asset: Address,
    /// Required approval threshold.
    pub threshold: u32,
    /// Number of signers.
    pub signer_count: u32,
    /// Current balance (in stroops).
    pub balance: i128,
    /// Total transactions proposed.
    pub tx_count: u64,
    /// Current policy version.
    pub policy_version: u32,
}

// ============================================================================
// Contract Implementation
// ============================================================================

#[contract]
pub struct TreasuryContract;

#[contractimpl]
impl TreasuryContract {
    // ========================================================================
    // Initialization
    // ========================================================================

    /// Initialize the treasury contract with an admin and approval threshold.
    ///
    /// # Arguments
    /// * `env` - The contract environment.
    /// * `admin` - The address that will administer the treasury.
    /// * `asset` - The Stellar Asset Contract address bound to this treasury.
    /// * `threshold` - The number of approvals required for withdrawals.
    /// * `signers` - Initial list of authorized signers.
    /// * `acl_address` - The access-control contract address for RBAC enforcement.
    ///
    /// # Errors
    /// * `Error::AlreadyInitialized` - If the contract was already initialized.
    /// * `Error::InvalidThreshold` - If threshold is 0 or exceeds signer count.
    /// * `Error::DuplicateSigner` - If `signers` contains duplicate addresses.
    pub fn initialize(
        env: Env,
        admin: Address,
        asset: Address,
        threshold: u32,
        signers: Vec<Address>,
        acl_address: Address,
    ) -> Result<(), Error> {
        // Prevent re-initialization
        if env.storage().instance().has(&DataKey::Initialized) {
            return Err(Error::AlreadyInitialized);
        }

        // Validate unique signers
        let mut unique_signers = Vec::new(&env);
        for s in signers.iter() {
            if unique_signers.contains(s.clone()) {
                return Err(Error::DuplicateSigner);
            }
            unique_signers.push_back(s.clone());
        }

        // Validate threshold against unique signers
        let signer_count = unique_signers.len();
        if threshold == 0 || threshold > signer_count {
            return Err(Error::InvalidThreshold);
        }

        // Verify admin has Admin+ role in ACL
        let acl_client = AccessControlContractClient::new(&env, &acl_address);
        if !acl_client.is_admin_or_above(&admin) {
            return Err(Error::Unauthorized);
        }

        admin.require_auth();

        // Store all initial state
        env.storage().instance().set(&DataKey::Initialized, &true);
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Asset, &asset);
        env.storage().instance().set(&DataKey::Threshold, &threshold);
        env.storage().instance().set(&DataKey::Signers, &unique_signers);
        env.storage().instance().set(&DataKey::Balance, &0_i128);
        env.storage().instance().set(&DataKey::TxCounter, &0_u64);
        env.storage().instance().set(&DataKey::PolicyVersion, &1_u32);
        env.storage().instance().set(&DataKey::AclAddress, &acl_address);

        // Emit initialization event
        env.events().publish(
            (symbol_short!("treasury"), symbol_short!("init")),
            (admin.clone(), asset.clone(), threshold, signer_count),
        );

        log!(&env, "Treasury initialized with {} signers, threshold {}, asset {:?}", signer_count, threshold, asset);
        Ok(())
    }

    // ========================================================================
    // Deposits
    // ========================================================================

    /// Deposit funds into the treasury.
    ///
    /// # Arguments
    /// * `env` - The contract environment.
    /// * `from` - The address depositing funds.
    /// * `amount` - The amount to deposit (in stroops).
    ///
    /// # Errors
    /// * `Error::NotInitialized` - If the contract is not initialized.
    /// * `Error::InvalidAmount` - If the amount is zero or negative.
    pub fn deposit(env: Env, from: Address, amount: i128) -> Result<(), Error> {
        Self::require_initialized(&env)?;

        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        from.require_auth();

        // Pull the bound asset address
        let asset: Address = env
            .storage()
            .instance()
            .get(&DataKey::Asset)
            .ok_or(Error::NotInitialized)?;
            
        let contract_address = env.current_contract_address();
        let token_client = token::Client::new(&env, &asset);
        
        // Transfer tokens from the depositor to the treasury contract.
        // Requires the depositor to have authorized this transfer.
        token_client.transfer(&from, &contract_address, &amount);

        // Update balance tracking
        let current_balance: i128 = env
            .storage()
            .instance()
            .get(&DataKey::Balance)
            .unwrap_or(0);
        let new_balance = current_balance + amount;
        env.storage()
            .instance()
            .set(&DataKey::Balance, &new_balance);

        // Emit deposit event
        env.events().publish(
            (symbol_short!("treasury"), symbol_short!("deposit")),
            (from.clone(), amount, new_balance),
        );

        log!(&env, "Deposit of {} from {:?}, new balance: {}", amount, from, new_balance);
        Ok(())
    }

    // ========================================================================
    // Withdrawal Proposals
    // ========================================================================

    /// Propose a withdrawal from the treasury.
    /// Only authorized signers can propose withdrawals.
    ///
    /// # Arguments
    /// * `env` - The contract environment.
    /// * `proposer` - The signer proposing the withdrawal.
    /// * `to` - The destination address.
    /// * `amount` - The amount to withdraw.
    /// * `memo` - A short description of the withdrawal.
    /// * `expires_at` - Timestamp when the transaction expires.
    ///
    /// # Returns
    /// The ID of the created transaction proposal.
    ///
    /// # Errors
    /// * `Error::NotInitialized` - If the contract is not initialized.
    /// * `Error::NotASigner` - If the proposer is not an authorized signer.
    /// * `Error::InvalidAmount` - If the amount is zero or negative.
    /// * `Error::InsufficientFunds` - If treasury balance is less than amount.
    /// * `Error::InvalidExpiry` - If expiry is in the past.
    pub fn propose_withdrawal(
        env: Env,
        proposer: Address,
        to: Address,
        amount: i128,
        memo: Symbol,
        expires_at: u64,
    ) -> Result<u64, Error> {
        Self::require_initialized(&env)?;
        Self::require_signer(&env, &proposer)?;

        proposer.require_auth();

        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        if expires_at <= env.ledger().timestamp() {
            return Err(Error::InvalidExpiry);
        }

        // Check sufficient balance
        let balance: i128 = env
            .storage()
            .instance()
            .get(&DataKey::Balance)
            .unwrap_or(0);
        if balance < amount {
            return Err(Error::InsufficientFunds);
        }

        // Get and increment counter
        let tx_id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::TxCounter)
            .unwrap_or(0);
        let next_id = tx_id + 1;
        env.storage()
            .instance()
            .set(&DataKey::TxCounter, &next_id);

        // Create initial approval list with proposer
        let mut approvals = Vec::new(&env);
        approvals.push_back(proposer.clone());

        // Build transaction proposal
        let transaction = Transaction {
            id: next_id,
            to: to.clone(),
            amount,
            memo: memo.clone(),
            approvals,
            executed: false,
            created_at: env.ledger().timestamp(),
            proposer: proposer.clone(),
            expires_at,
            canceled: false,
            policy_version: env.storage().instance().get(&DataKey::PolicyVersion).unwrap_or(1),
        };

        // Store transaction
        env.storage()
            .persistent()
            .set(&DataKey::Transaction(next_id), &transaction);

        // Emit proposal event
        env.events().publish(
            (symbol_short!("treasury"), symbol_short!("propose")),
            (next_id, proposer.clone(), to, amount),
        );

        log!(&env, "Withdrawal proposal #{} created by {:?} for {}", next_id, proposer, amount);
        Ok(next_id)
    }

    // ========================================================================
    // Multi-Sig Approval
    // ========================================================================

    /// Approve a pending withdrawal transaction.
    /// Once the threshold is reached, the transaction can be executed.
    ///
    /// # Arguments
    /// * `env` - The contract environment.
    /// * `signer` - The signer approving the transaction.
    /// * `tx_id` - The ID of the transaction to approve.
    ///
    /// # Errors
    /// * `Error::NotASigner` - If the caller is not a signer.
    /// * `Error::TransactionNotFound` - If the transaction doesn't exist.
    /// * `Error::AlreadyApproved` - If signer already approved.
    /// * `Error::AlreadyExecuted` - If transaction is already executed.
    pub fn approve(env: Env, signer: Address, tx_id: u64) -> Result<u32, Error> {
        Self::require_initialized(&env)?;
        Self::require_signer(&env, &signer)?;

        signer.require_auth();

        // Load transaction
        let mut transaction: Transaction = env
            .storage()
            .persistent()
            .get(&DataKey::Transaction(tx_id))
            .ok_or(Error::TransactionNotFound)?;

        if transaction.executed {
            return Err(Error::AlreadyExecuted);
        }
        if transaction.canceled {
            return Err(Error::TransactionCanceled);
        }
        if env.ledger().timestamp() > transaction.expires_at {
            return Err(Error::TransactionExpired);
        }
        let current_policy_version: u32 = env.storage().instance().get(&DataKey::PolicyVersion).unwrap_or(1);
        if transaction.policy_version != current_policy_version {
            return Err(Error::PolicyInvalidated);
        }

        // Check if already approved by this signer
        for i in 0..transaction.approvals.len() {
            if transaction.approvals.get(i).unwrap() == signer {
                return Err(Error::AlreadyApproved);
            }
        }

        // Add approval
        transaction.approvals.push_back(signer.clone());
        let approval_count = transaction.approvals.len();

        // Save updated transaction
        env.storage()
            .persistent()
            .set(&DataKey::Transaction(tx_id), &transaction);

        // Emit approval event
        env.events().publish(
            (symbol_short!("treasury"), symbol_short!("approve")),
            (tx_id, signer.clone(), approval_count),
        );

        log!(&env, "Transaction #{} approved by {:?} ({} approvals)", tx_id, signer, approval_count);
        Ok(approval_count)
    }

    /// Execute a fully approved withdrawal transaction.
    /// Requires the approval count to meet or exceed the threshold.
    /// Transfers the real asset to the recipient atomically with the
    /// state change. Guards are re-verified immediately before the
    /// transfer to prevent double-execute and stale-policy attacks.
    ///
    /// # Arguments
    /// * `env` - The contract environment.
    /// * `executor` - The signer executing the transaction.
    /// * `tx_id` - The ID of the transaction to execute.
    ///
    /// # Errors
    /// * `Error::NotASigner` - If executor is not a signer.
    /// * `Error::TransactionNotFound` - If the transaction doesn't exist.
    /// * `Error::AlreadyExecuted` - If already executed.
    /// * `Error::Unauthorized` - If approval threshold not met.
    pub fn execute(env: Env, executor: Address, tx_id: u64) -> Result<(), Error> {
        Self::require_initialized(&env)?;
        Self::require_signer(&env, &executor)?;

        executor.require_auth();

        let mut transaction: Transaction = env
            .storage()
            .persistent()
            .get(&DataKey::Transaction(tx_id))
            .ok_or(Error::TransactionNotFound)?;

        if transaction.executed {
            return Err(Error::AlreadyExecuted);
        }
        if transaction.canceled {
            return Err(Error::TransactionCanceled);
        }
        if env.ledger().timestamp() > transaction.expires_at {
            return Err(Error::TransactionExpired);
        }
        let current_policy_version: u32 = env.storage().instance().get(&DataKey::PolicyVersion).unwrap_or(1);
        if transaction.policy_version != current_policy_version {
            return Err(Error::PolicyInvalidated);
        }

        // Check threshold
        let threshold: u32 = env
            .storage()
            .instance()
            .get(&DataKey::Threshold)
            .unwrap_or(1);
        if transaction.approvals.len() < threshold {
            return Err(Error::Unauthorized);
        }

        // Verify internal balance tracking
        let current_balance: i128 = env
            .storage()
            .instance()
            .get(&DataKey::Balance)
            .unwrap_or(0);
        if current_balance < transaction.amount {
            return Err(Error::InsufficientFunds);
        }

        // Perform the real asset transfer before state mutation.
        // In Soroban the entire invocation is atomic — if the transfer
        // panics the state changes below are never committed, so there
        // is no double-spend or stuck-funds risk.
        let asset: Address = env
            .storage()
            .instance()
            .get(&DataKey::Asset)
            .ok_or(Error::NotInitialized)?;
        let contract_address = env.current_contract_address();
        let token_client = token::Client::new(&env, &asset);

        let contract_token_balance = token_client.balance(&contract_address);
        if contract_token_balance < transaction.amount {
            return Err(Error::InsufficientFunds);
        }

        token_client.transfer(&contract_address, &transaction.to, &transaction.amount);

        // Mark executed and deduct tracked balance — durable and terminal
        transaction.executed = true;
        let new_balance = current_balance - transaction.amount;
        env.storage()
            .instance()
            .set(&DataKey::Balance, &new_balance);
        env.storage()
            .persistent()
            .set(&DataKey::Transaction(tx_id), &transaction);

        // Emit execution event
        env.events().publish(
            (symbol_short!("treasury"), symbol_short!("execute")),
            (tx_id, transaction.to.clone(), transaction.amount, new_balance),
        );

        log!(&env, "Transaction #{} executed: {} to {:?}", tx_id, transaction.amount, transaction.to);
        Ok(())
    }

    /// Revoke a previous approval for a transaction.
    /// Can only be done before execution.
    pub fn revoke_approval(env: Env, signer: Address, tx_id: u64) -> Result<u32, Error> {
        Self::require_initialized(&env)?;
        Self::require_signer(&env, &signer)?;

        signer.require_auth();

        let mut transaction: Transaction = env
            .storage()
            .persistent()
            .get(&DataKey::Transaction(tx_id))
            .ok_or(Error::TransactionNotFound)?;

        if transaction.executed {
            return Err(Error::AlreadyExecuted);
        }
        if transaction.canceled {
            return Err(Error::TransactionCanceled);
        }
        if env.ledger().timestamp() > transaction.expires_at {
            return Err(Error::TransactionExpired);
        }
        let current_policy_version: u32 = env.storage().instance().get(&DataKey::PolicyVersion).unwrap_or(1);
        if transaction.policy_version != current_policy_version {
            return Err(Error::PolicyInvalidated);
        }

        let mut new_approvals = Vec::new(&env);
        let mut found = false;
        for i in 0..transaction.approvals.len() {
            let s = transaction.approvals.get(i).unwrap();
            if s == signer {
                found = true;
            } else {
                new_approvals.push_back(s);
            }
        }

        if !found {
            return Err(Error::NotApproved);
        }

        transaction.approvals = new_approvals;
        let approval_count = transaction.approvals.len();

        env.storage()
            .persistent()
            .set(&DataKey::Transaction(tx_id), &transaction);

        env.events().publish(
            (symbol_short!("treasury"), symbol_short!("revoke")),
            (tx_id, signer.clone(), approval_count),
        );

        log!(&env, "Transaction #{} approval revoked by {:?}", tx_id, signer);
        Ok(approval_count)
    }

    /// Cancel a transaction. Only the proposer or the admin can cancel.
    pub fn cancel_withdrawal(env: Env, caller: Address, tx_id: u64) -> Result<(), Error> {
        Self::require_initialized(&env)?;
        caller.require_auth();

        let mut transaction: Transaction = env
            .storage()
            .persistent()
            .get(&DataKey::Transaction(tx_id))
            .ok_or(Error::TransactionNotFound)?;

        if transaction.executed {
            return Err(Error::AlreadyExecuted);
        }
        if transaction.canceled {
            return Err(Error::TransactionCanceled);
        }

        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        if caller != transaction.proposer && caller != admin {
            return Err(Error::Unauthorized);
        }

        transaction.canceled = true;

        env.storage()
            .persistent()
            .set(&DataKey::Transaction(tx_id), &transaction);

        env.events().publish(
            (symbol_short!("treasury"), symbol_short!("cancel")),
            (tx_id, caller.clone()),
        );

        log!(&env, "Transaction #{} canceled by {:?}", tx_id, caller);
        Ok(())
    }

    // ========================================================================
    // Signer Management
    // ========================================================================

    /// Add a new signer to the multi-sig treasury.
    /// Only the admin can add signers.
    pub fn add_signer(env: Env, admin: Address, new_signer: Address) -> Result<(), Error> {
        Self::require_initialized(&env)?;
        Self::require_admin(&env, &admin)?;

        admin.require_auth();

        let mut signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .unwrap_or(Vec::new(&env));

        // Check if already a signer
        for i in 0..signers.len() {
            if signers.get(i).unwrap() == new_signer {
                return Err(Error::AlreadySigner);
            }
        }

        signers.push_back(new_signer.clone());
        env.storage().instance().set(&DataKey::Signers, &signers);

        let mut policy_version: u32 = env.storage().instance().get(&DataKey::PolicyVersion).unwrap_or(1);
        policy_version += 1;
        env.storage().instance().set(&DataKey::PolicyVersion, &policy_version);

        env.events().publish(
            (symbol_short!("treasury"), symbol_short!("add_sig")),
            (new_signer.clone(), signers.len()),
        );

        Ok(())
    }

    /// Remove a signer from the multi-sig treasury.
    /// Only the admin can remove signers. Cannot reduce below threshold.
    pub fn remove_signer(env: Env, admin: Address, signer: Address) -> Result<(), Error> {
        Self::require_initialized(&env)?;
        Self::require_admin(&env, &admin)?;

        admin.require_auth();

        let signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .unwrap_or(Vec::new(&env));

        let threshold: u32 = env
            .storage()
            .instance()
            .get(&DataKey::Threshold)
            .unwrap_or(1);

        // Cannot remove if it would breach threshold
        if signers.len() <= threshold {
            return Err(Error::ThresholdBreach);
        }

        // Find and remove the signer
        let mut new_signers = Vec::new(&env);
        let mut found = false;
        for i in 0..signers.len() {
            let s = signers.get(i).unwrap();
            if s == signer {
                found = true;
            } else {
                new_signers.push_back(s);
            }
        }

        if !found {
            return Err(Error::NotASigner);
        }

        env.storage()
            .instance()
            .set(&DataKey::Signers, &new_signers);

        let mut policy_version: u32 = env.storage().instance().get(&DataKey::PolicyVersion).unwrap_or(1);
        policy_version += 1;
        env.storage().instance().set(&DataKey::PolicyVersion, &policy_version);

        env.events().publish(
            (symbol_short!("treasury"), symbol_short!("rem_sig")),
            (signer.clone(), new_signers.len()),
        );

        Ok(())
    }

    /// Update the approval threshold.
    /// Only the admin can change the threshold.
    pub fn set_threshold(env: Env, admin: Address, new_threshold: u32) -> Result<(), Error> {
        Self::require_initialized(&env)?;
        Self::require_admin(&env, &admin)?;

        admin.require_auth();

        let signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .unwrap_or(Vec::new(&env));

        if new_threshold == 0 || new_threshold > signers.len() {
            return Err(Error::InvalidThreshold);
        }

        env.storage()
            .instance()
            .set(&DataKey::Threshold, &new_threshold);

        let mut policy_version: u32 = env.storage().instance().get(&DataKey::PolicyVersion).unwrap_or(1);
        policy_version += 1;
        env.storage().instance().set(&DataKey::PolicyVersion, &policy_version);

        env.events().publish(
            (symbol_short!("treasury"), symbol_short!("thresh")),
            new_threshold,
        );

        Ok(())
    }

    // ========================================================================
    // Query Functions
    // ========================================================================

    /// Get the current treasury balance.
    pub fn get_balance(env: Env) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::Balance)
            .unwrap_or(0)
    }

    /// Get the treasury configuration.
    pub fn get_config(env: Env) -> Result<TreasuryConfig, Error> {
        Self::require_initialized(&env)?;

        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        let asset: Address = env
            .storage()
            .instance()
            .get(&DataKey::Asset)
            .ok_or(Error::NotInitialized)?;
        let threshold: u32 = env
            .storage()
            .instance()
            .get(&DataKey::Threshold)
            .unwrap_or(1);
        let signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .unwrap_or(Vec::new(&env));
        let balance: i128 = env
            .storage()
            .instance()
            .get(&DataKey::Balance)
            .unwrap_or(0);
        let tx_count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::TxCounter)
            .unwrap_or(0);
        let policy_version: u32 = env
            .storage()
            .instance()
            .get(&DataKey::PolicyVersion)
            .unwrap_or(1);

        Ok(TreasuryConfig {
            admin,
            asset,
            threshold,
            signer_count: signers.len(),
            balance,
            tx_count,
            policy_version,
        })
    }

    /// Get a specific transaction by ID.
    pub fn get_transaction(env: Env, tx_id: u64) -> Result<Transaction, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Transaction(tx_id))
            .ok_or(Error::TransactionNotFound)
    }

    /// Get the list of current signers.
    pub fn get_signers(env: Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get(&DataKey::Signers)
            .unwrap_or(Vec::new(&env))
    }

    // ========================================================================
    // Admin Functions
    // ========================================================================

    /// Transfer admin role to a new address.
    pub fn transfer_admin(env: Env, current_admin: Address, new_admin: Address) -> Result<(), Error> {
        Self::require_initialized(&env)?;
        Self::require_admin(&env, &current_admin)?;

        current_admin.require_auth();

        Self::require_acl_admin_or_above(&env, &new_admin)?;

        env.storage()
            .instance()
            .set(&DataKey::Admin, &new_admin);

        env.events().publish(
            (symbol_short!("treasury"), symbol_short!("admin")),
            (current_admin, new_admin.clone()),
        );

        Ok(())
    }

    /// Upgrade the contract WASM. Admin only.
    pub fn upgrade(env: Env, admin: Address, new_wasm_hash: soroban_sdk::BytesN<32>) -> Result<(), Error> {
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

    fn require_signer(env: &Env, caller: &Address) -> Result<(), Error> {
        let signers: Vec<Address> = env
            .storage()
            .instance()
            .get(&DataKey::Signers)
            .unwrap_or(Vec::new(env));

        let mut is_signer = false;
        for i in 0..signers.len() {
            if signers.get(i).unwrap() == *caller {
                is_signer = true;
                break;
            }
        }
        if !is_signer {
            return Err(Error::NotASigner);
        }
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod test {
    use soroban_sdk::testutils::Events;
    use soroban_sdk::testutils::Ledger as _;
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::Env;
    use stellar_sentinel_access_control::{
        AccessControlContract, AccessControlContractClient,
    };

    fn deploy_acl(env: &Env, owner: &Address) -> Address {
        let acl_id = env.register_contract(None, AccessControlContract);
        let acl_client = AccessControlContractClient::new(env, &acl_id);
        acl_client.initialize(owner);
        acl_id
    }

    fn setup_contract() -> (Env, Address, Address, TreasuryContractClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, crate::TreasuryContract);
        let client = TreasuryContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let acl_id = deploy_acl(&env, &admin);
        (env, admin, acl_id, client)
    }

    fn setup_contract_with_token(
        init_balance: i128,
    ) -> (Env, Address, Address, TreasuryContractClient<'static>, soroban_sdk::Address, token::StellarAssetClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let acl_id = deploy_acl(&env, &admin);
        let asset_contract = env.register_stellar_asset_contract_v2(admin.clone());
        let asset = asset_contract.address();
        let contract_id = env.register_contract(None, crate::TreasuryContract);
        let client = TreasuryContractClient::new(&env, &contract_id);
        let sac_client = token::StellarAssetClient::new(&env, &asset);
        if init_balance > 0 {
            sac_client.mint(&contract_id, &init_balance);
        }
        (env, admin, acl_id, client, asset, sac_client)
    }

    #[test]
    fn test_initialize() {
        let (env, admin, acl_id, client) = setup_contract();

        let signer1 = Address::generate(&env);
        let signer2 = Address::generate(&env);
        let signer3 = Address::generate(&env);

        let asset = Address::generate(&env);

        let signers = Vec::from_array(
            &env,
            [signer1.clone(), signer2.clone(), signer3.clone()],
        );

        client.initialize(&admin, &asset, &2, &signers, &acl_id);

        let config = client.get_config();
        assert_eq!(config.admin, admin);
        assert_eq!(config.asset, asset);
        assert_eq!(config.threshold, 2);
        assert_eq!(config.signer_count, 3);
        assert_eq!(config.balance, 0);
    }

    #[test]
    fn test_deposit() {
        let (env, admin, acl_id, client, asset, sac_client) = setup_contract_with_token(0);

        let signer1 = Address::generate(&env);
        let signers = Vec::from_array(&env, [signer1.clone()]);
        client.initialize(&admin, &asset, &1, &signers, &acl_id);

        let depositor = Address::generate(&env);
        sac_client.mint(&depositor, &1_000_000);
        client.deposit(&depositor, &1_000_000);

        assert_eq!(client.get_balance(), 1_000_000);
    }

    #[test]
    fn test_propose_and_approve() {
        let (env, admin, acl_id, client, asset, sac_client) = setup_contract_with_token(5_000_000);

        let signer1 = Address::generate(&env);
        let signer2 = Address::generate(&env);
        let signers = Vec::from_array(&env, [signer1.clone(), signer2.clone()]);
        client.initialize(&admin, &asset, &2, &signers, &acl_id);

        // Deposit some funds
        sac_client.mint(&signer1, &5_000_000);
        client.deposit(&signer1, &5_000_000);

        // Propose withdrawal
        let recipient = Address::generate(&env);
        let tx_id = client.propose_withdrawal(
            &signer1,
            &recipient,
            &1_000_000,
            &symbol_short!("rent"),
            &(env.ledger().timestamp() + 3600),
        );
        assert_eq!(tx_id, 1);

        // Second signer approves
        let approval_count = client.approve(&signer2, &tx_id);
        assert_eq!(approval_count, 2);

        // Execute
        client.execute(&signer1, &tx_id);

        // Check balance deducted
        assert_eq!(client.get_balance(), 4_000_000);

        // Check transaction marked as executed
        let tx = client.get_transaction(&tx_id);
        assert_eq!(tx.executed, true);
    }

    #[test]
    #[should_panic(expected = "HostError: Error(Contract, #19)")]
    fn test_duplicate_signer_rejected() {
        let (env, admin, acl_id, client) = setup_contract();
        let signer1 = Address::generate(&env);
        let asset = Address::generate(&env);
        let signers = Vec::from_array(&env, [signer1.clone(), signer1.clone()]);
        
        client.initialize(&admin, &asset, &1, &signers, &acl_id);
    }

    #[test]
    #[should_panic(expected = "HostError: Error(Contract, #2)")]
    fn test_already_initialized() {
        let (env, admin, acl_id, client) = setup_contract();
        let signer1 = Address::generate(&env);
        let asset = Address::generate(&env);
        let signers = Vec::from_array(&env, [signer1.clone()]);
        
        client.initialize(&admin, &asset, &1, &signers, &acl_id);
        // Attempt re-initialization
        let new_asset = Address::generate(&env);
        client.initialize(&admin, &new_asset, &1, &signers, &acl_id);
    }

    #[test]
    #[should_panic(expected = "HostError: Error(Contract, #6)")]
    fn test_invalid_threshold_zero() {
        let (env, admin, acl_id, client) = setup_contract();
        let signer1 = Address::generate(&env);
        let asset = Address::generate(&env);
        let signers = Vec::from_array(&env, [signer1.clone()]);
        
        client.initialize(&admin, &asset, &0, &signers, &acl_id);
    }

    #[test]
    #[should_panic(expected = "HostError: Error(Contract, #6)")]
    fn test_invalid_threshold_exceeds_signers() {
        let (env, admin, acl_id, client) = setup_contract();
        let signer1 = Address::generate(&env);
        let asset = Address::generate(&env);
        let signers = Vec::from_array(&env, [signer1.clone()]);
        
        client.initialize(&admin, &asset, &2, &signers, &acl_id);
    }

    #[test]
    #[should_panic(expected = "HostError: Error(Contract, #1)")]
    fn test_storage_lifecycle_not_initialized_deposit() {
        let (env, _, _, client) = setup_contract();
        let depositor = Address::generate(&env);
        client.deposit(&depositor, &100);
    }

    #[test]
    fn test_invariant_balance_tracking() {
        let (env, admin, acl_id, client, asset, sac_client) = setup_contract_with_token(1_500);
        let signer1 = Address::generate(&env);
        let signers = Vec::from_array(&env, [signer1.clone()]);
        client.initialize(&admin, &asset, &1, &signers, &acl_id);

        assert_eq!(client.get_balance(), 0);

        let depositor = Address::generate(&env);
        sac_client.mint(&depositor, &1_000);
        client.deposit(&depositor, &1_000);
        assert_eq!(client.get_balance(), 1_000);

        sac_client.mint(&depositor, &500);
        client.deposit(&depositor, &500);
        assert_eq!(client.get_balance(), 1_500);

        let recipient = Address::generate(&env);
        let tx_id = client.propose_withdrawal(&signer1, &recipient, &500, &symbol_short!("pay"), &2000);
        client.execute(&signer1, &tx_id);

        assert_eq!(client.get_balance(), 1_000);
    }

    #[test]
    #[should_panic(expected = "HostError: Error(Contract, #5)")]
    fn test_invariant_insufficient_funds_proposal() {
        let (env, admin, acl_id, client) = setup_contract();
        let signer1 = Address::generate(&env);
        let asset = Address::generate(&env);
        let signers = Vec::from_array(&env, [signer1.clone()]);
        client.initialize(&admin, &asset, &1, &signers, &acl_id);

        let recipient = Address::generate(&env);
        client.propose_withdrawal(&signer1, &recipient, &100, &symbol_short!("pay"), &2000);
    }

    #[test]
    fn test_event_emission_coverage() {
        let (env, admin, acl_id, client, asset, sac_client) = setup_contract_with_token(500);
        let signer1 = Address::generate(&env);
        let signers = Vec::from_array(&env, [signer1.clone()]);
        
        let events_before_init = env.events().all().len();
        client.initialize(&admin, &asset, &1, &signers, &acl_id);
        let events_after_init = env.events().all().len();
        assert!(events_after_init > events_before_init);

        let depositor = Address::generate(&env);
        sac_client.mint(&depositor, &500);
        client.deposit(&depositor, &500);
        let events_after_deposit = env.events().all().len();
        assert!(events_after_deposit > events_after_init);
        
        let recipient = Address::generate(&env);
        let tx_id = client.propose_withdrawal(&signer1, &recipient, &500, &symbol_short!("pay"), &2000);
        let events_after_propose = env.events().all().len();
        assert!(events_after_propose > events_after_deposit);

        client.execute(&signer1, &tx_id);
        let events_after_execute = env.events().all().len();
        assert!(events_after_execute > events_after_propose);
    }

    #[test]
    #[should_panic(expected = "HostError: Error(Contract, #12)")]
    fn test_invariant_threshold_breach_prevention() {
        let (env, admin, acl_id, client) = setup_contract();
        let signer1 = Address::generate(&env);
        let asset = Address::generate(&env);
        let signers = Vec::from_array(&env, [signer1.clone()]);
        client.initialize(&admin, &asset, &1, &signers, &acl_id);

        // Cannot remove the only signer as it breaches the threshold
        client.remove_signer(&admin, &signer1);
    }

    #[test]
    fn test_execute_transfers_real_asset_atomically() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let acl_id = deploy_acl(&env, &admin);
        let signer1 = Address::generate(&env);
        let signer2 = Address::generate(&env);
        let recipient = Address::generate(&env);
        let signers = Vec::from_array(&env, [signer1.clone(), signer2.clone()]);

        let asset_contract = env.register_stellar_asset_contract_v2(admin.clone());
        let asset = asset_contract.address();
        let contract_id = env.register_contract(None, TreasuryContract);
        let client = TreasuryContractClient::new(&env, &contract_id);

        client.initialize(&admin, &asset, &2, &signers, &acl_id);

        let token_client = token::Client::new(&env, &asset);
        let sac_client = token::StellarAssetClient::new(&env, &asset);
        sac_client.mint(&contract_id, &5_000_000);

        sac_client.mint(&signer1, &5_000_000);
        client.deposit(&signer1, &5_000_000);

        let tx_id = client.propose_withdrawal(
            &signer1,
            &recipient,
            &2_000_000,
            &symbol_short!("w"),
            &(env.ledger().timestamp() + 3600),
        );
        client.approve(&signer2, &tx_id);

        let recipient_balance_before: i128 = token_client.balance(&recipient);
        let contract_balance_before: i128 = token_client.balance(&contract_id);

        client.execute(&signer1, &tx_id);

        let recipient_balance_after: i128 = token_client.balance(&recipient);
        let contract_balance_after: i128 = token_client.balance(&contract_id);

        assert_eq!(recipient_balance_after, recipient_balance_before + 2_000_000);
        assert_eq!(contract_balance_after, contract_balance_before - 2_000_000);
        assert_eq!(client.get_balance(), 3_000_000);

        let tx = client.get_transaction(&tx_id);
        assert_eq!(tx.executed, true);
    }

    #[test]
    fn test_double_execute_reverts_with_real_token() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let acl_id = deploy_acl(&env, &admin);
        let signer1 = Address::generate(&env);
        let signer2 = Address::generate(&env);
        let recipient = Address::generate(&env);
        let signers = Vec::from_array(&env, [signer1.clone(), signer2.clone()]);

        let asset_contract = env.register_stellar_asset_contract_v2(admin.clone());
        let asset = asset_contract.address();
        let contract_id = env.register_contract(None, TreasuryContract);
        let client = TreasuryContractClient::new(&env, &contract_id);

        client.initialize(&admin, &asset, &2, &signers, &acl_id);

        let sac_client = token::StellarAssetClient::new(&env, &asset);
        sac_client.mint(&contract_id, &5_000_000);

        sac_client.mint(&signer1, &5_000_000);
        client.deposit(&signer1, &5_000_000);

        let tx_id = client.propose_withdrawal(
            &signer1,
            &recipient,
            &2_000_000,
            &symbol_short!("w"),
            &(env.ledger().timestamp() + 3600),
        );
        client.approve(&signer2, &tx_id);

        client.execute(&signer1, &tx_id);

        let balance_after_first = client.get_balance();

        assert_eq!(
            client.try_execute(&signer1, &tx_id),
            Err(Ok(Error::AlreadyExecuted))
        );
        assert_eq!(client.get_balance(), balance_after_first);
    }

    #[test]
    fn test_execute_after_expiry_reverts_with_real_token() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let acl_id = deploy_acl(&env, &admin);
        let signer1 = Address::generate(&env);
        let signer2 = Address::generate(&env);
        let recipient = Address::generate(&env);
        let signers = Vec::from_array(&env, [signer1.clone(), signer2.clone()]);

        let asset_contract = env.register_stellar_asset_contract_v2(admin.clone());
        let asset = asset_contract.address();
        let contract_id = env.register_contract(None, TreasuryContract);
        let client = TreasuryContractClient::new(&env, &contract_id);

        client.initialize(&admin, &asset, &2, &signers, &acl_id);

        let sac_client = token::StellarAssetClient::new(&env, &asset);
        sac_client.mint(&contract_id, &5_000_000);

        sac_client.mint(&signer1, &5_000_000);
        client.deposit(&signer1, &5_000_000);

        let expiry = env.ledger().timestamp() + 500;
        let tx_id = client.propose_withdrawal(
            &signer1,
            &recipient,
            &2_000_000,
            &symbol_short!("w"),
            &expiry,
        );
        client.approve(&signer2, &tx_id);

        env.ledger().set_timestamp(expiry + 1);

        let token_client = token::Client::new(&env, &asset);
        let recipient_balance_before: i128 = token_client.balance(&recipient);

        assert_eq!(
            client.try_execute(&signer1, &tx_id),
            Err(Ok(Error::TransactionExpired))
        );

        let recipient_balance_after: i128 = token_client.balance(&recipient);
        assert_eq!(recipient_balance_after, recipient_balance_before);
        assert_eq!(client.get_balance(), 5_000_000);
    }

    #[test]
    fn test_execute_after_policy_change_reverts_with_real_token() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let acl_id = deploy_acl(&env, &admin);
        let signer1 = Address::generate(&env);
        let signer2 = Address::generate(&env);
        let recipient = Address::generate(&env);
        let signers = Vec::from_array(&env, [signer1.clone(), signer2.clone()]);

        let asset_contract = env.register_stellar_asset_contract_v2(admin.clone());
        let asset = asset_contract.address();
        let contract_id = env.register_contract(None, TreasuryContract);
        let client = TreasuryContractClient::new(&env, &contract_id);

        client.initialize(&admin, &asset, &2, &signers, &acl_id);

        let sac_client = token::StellarAssetClient::new(&env, &asset);
        sac_client.mint(&contract_id, &5_000_000);

        sac_client.mint(&signer1, &5_000_000);
        client.deposit(&signer1, &5_000_000);

        let tx_id = client.propose_withdrawal(
            &signer1,
            &recipient,
            &2_000_000,
            &symbol_short!("w"),
            &(env.ledger().timestamp() + 3600),
        );

        let new_signer = Address::generate(&env);
        client.add_signer(&admin, &new_signer);

        let token_client = token::Client::new(&env, &asset);
        let recipient_balance_before: i128 = token_client.balance(&recipient);

        assert_eq!(
            client.try_execute(&signer1, &tx_id),
            Err(Ok(Error::PolicyInvalidated))
        );

        let recipient_balance_after: i128 = token_client.balance(&recipient);
        assert_eq!(recipient_balance_after, recipient_balance_before);
        assert_eq!(client.get_balance(), 5_000_000);
    }

    #[test]
    fn test_execute_insufficient_real_balance_reverts() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let acl_id = deploy_acl(&env, &admin);
        let signer1 = Address::generate(&env);
        let signer2 = Address::generate(&env);
        let recipient = Address::generate(&env);
        let signers = Vec::from_array(&env, [signer1.clone(), signer2.clone()]);

        let asset_contract = env.register_stellar_asset_contract_v2(admin.clone());
        let asset = asset_contract.address();
        let contract_id = env.register_contract(None, TreasuryContract);
        let client = TreasuryContractClient::new(&env, &contract_id);

        client.initialize(&admin, &asset, &2, &signers, &acl_id);

        let sac_client = token::StellarAssetClient::new(&env, &asset);


        sac_client.mint(&signer1, &1_000_000);
        client.deposit(&signer1, &1_000_000);

        let tx_id = client.propose_withdrawal(
            &signer1,
            &recipient,
            &1_000_000,
            &symbol_short!("w"),
            &(env.ledger().timestamp() + 3600),
        );
        client.approve(&signer2, &tx_id);

        sac_client.mint(&signer1, &1_000_000);
        let burn_token_client = token::Client::new(&env, &asset);
        burn_token_client.transfer(&contract_id, &signer1, &500_000);

        let token_client = token::Client::new(&env, &asset);
        let recipient_balance_before: i128 = token_client.balance(&recipient);

        assert_eq!(
            client.try_execute(&signer1, &tx_id),
            Err(Ok(Error::InsufficientFunds))
        );

        let recipient_balance_after: i128 = token_client.balance(&recipient);
        assert_eq!(recipient_balance_after, recipient_balance_before);
    }
}
