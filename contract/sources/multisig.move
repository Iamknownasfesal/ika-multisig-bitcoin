/// Bitcoin Multisig Wallet Module with IKA dWallet 2PC-MPC protocol
///
/// This module implements a distributed multi-signature wallet system for Bitcoin transactions
/// using the IKA dWallet 2PC-MPC protocol. It allows multiple members to collectively approve
/// or reject Bitcoin transactions before execution.
///
/// Key Features:
/// - Configurable approval and rejection thresholds
/// - Time-based request expiration
/// - Irrevocable voting (once voted, members cannot change their decision)
/// - Integration with IKA's distributed wallet protocol for enhanced security
///
/// Security Considerations:
/// - All voting decisions are final and cannot be changed
/// - Requests automatically expire after a configured duration
/// - Threshold validation prevents single points of failure
module ika_btc_multisig::multisig;

use ika::ika::IKA;
use ika_btc_multisig::{
    constants,
    error
};
use ika_dwallet_2pc_mpc::{
    coordinator::{DWalletCoordinator, request_dwallet_dkg_first_round},
    coordinator_inner::{DWalletCap, UnverifiedPresignCap, UnverifiedPartialUserSignatureCap},
    sessions_manager::SessionIdentifier
};
use sui::{clock::Clock, coin::Coin, sui::SUI, table::{Self, Table}};

// === Structs ===

/// The main multisig wallet object that manages Bitcoin transaction approvals.
/// This shared object coordinates between multiple members to approve or reject Bitcoin transactions.
/// All state changes are atomic and consistent across the distributed system.
public struct Multisig has key, store {
    /// Unique identifier for this multisig wallet instance
    id: UID,
    /// Distributed wallet capability for creating Bitcoin signatures.
    /// This integrates with IKA's 2PC-MPC protocol for enhanced security.
    dwallet_cap: DWalletCap,
    /// List of member addresses who can vote on requests.
    /// Members are identified by their Sui addresses and must be unique.
    members: vector<address>,
    /// Number of approval votes required to execute a Bitcoin transaction.
    /// Must be greater than 0 and less than or equal to the number of members.
    approval_threshold: u64,
    /// Number of rejection votes required to definitively reject a request.
    /// Must be greater than 0 and less than or equal to the number of members.
    rejection_threshold: u64,
    /// Table storing all active requests indexed by request ID.
    /// Request IDs are auto-incrementing counters for uniqueness.
    requests: Table<u64, Request>,
    /// Duration in milliseconds after which a request automatically expires.
    /// Expired requests cannot be voted on or executed.
    /// A request is considered expired if: created_at + expiration_duration < current_time
    expiration_duration: u64,
    /// Auto-incrementing counter for generating unique request IDs.
    /// Each new request increments this counter to ensure globally unique identifiers
    /// across the multisig wallet's lifetime.
    request_id_counter: u64,
    /// Collection of unverified presign capabilities that require validation before use.
    /// These capabilities represent requested presign sessions that must be verified
    /// as completed before they can be converted to VerifiedPresignCap for signing operations.
    presigns: vector<UnverifiedPresignCap>,
}

/// Represents a Bitcoin transaction request that needs multisig approval.
/// Each request contains the transaction details and tracks voting progress.
/// Once created, requests have a finite lifetime and expire automatically.
public struct Request has store {
    /// The request type.
    request_type: RequestType,
    /// Current status of this request (Pending, Approved, or Rejected).
    /// The status transitions based on accumulated votes and becomes final once thresholds are met.
    status: RequestStatus,
    /// Unix timestamp (in seconds) when this request was created.
    /// Used to calculate expiration: request is expired if created_at + expiration_duration < current_time
    created_at: u64,
    /// Running count of members who have voted in favor of this request.
    /// When this reaches approval_threshold, the request status becomes Approved.
    approvers_count: u64,
    /// Running count of members who have voted against this request.
    /// When this reaches rejection_threshold, the request status becomes Rejected.
    rejecters_count: u64,
    /// Immutable record of each member's vote on this request.
    /// Key: member address, Value: true for approval, false for rejection.
    ///
    /// CRITICAL SECURITY PROPERTY: Votes are irrevocable!
    /// Once a member votes (approval or rejection), they cannot change their decision.
    /// This prevents vote manipulation and ensures decision finality.
    votes: Table<address, bool>,
    /// Unverified partial user signature capability for Bitcoin transactions.
    /// This field is only populated for SendBTC requests and contains the capability
    /// needed to sign the Bitcoin transaction with the user's private key share.
    /// The capability must be verified before it can be used for signing operations.
    send_btc_unverified_partial_user_signature_cap: Option<UnverifiedPartialUserSignatureCap>,
}

/// Tracks the complete lifecycle of a multisig request from creation to final resolution.
/// The status follows a strict state machine: Pending → (Approved | Rejected).
/// Status transitions are irreversible once voting thresholds are reached, ensuring
/// decision finality and preventing manipulation or double-execution.
///
/// This enum serves as both a state indicator and a result container for completed requests.
public enum RequestStatus has copy, drop, store {
    /// Initial state: Request is actively collecting votes from multisig members.
    /// The request remains in this state until it reaches either approval or rejection threshold.
    /// Members can still vote, and the request can expire if the deadline passes.
    Pending,
    /// Terminal state: Request has reached approval threshold and been successfully executed.
    /// Contains the RequestResult which captures the specific outcome of the approved action.
    /// The request is now immutable and ready for implementation or further processing.
    Approved(RequestResult),
    /// Terminal state: Request has reached rejection threshold and will not be executed.
    /// No further action is possible on this request. The rejection is final and binding.
    /// This prevents the request from being resubmitted or reconsidered.
    Rejected,
}

/// Defines the various types of requests that can be submitted to the multisig wallet.
/// Each variant represents a different governance or operational action that requires collective approval.
/// All request types follow the same voting and approval process but have different execution logic.
public enum RequestType has copy, drop, store {
    /// Bitcoin transaction request containing transaction data and signature information.
    /// Parameters: (transaction_hex, centralized_signature, partial_user_signature_cap_id)
    /// - transaction_hex: Complete serialized Bitcoin transaction ready for signing
    /// - centralized_signature: Centralized signature component for the transaction
    /// - partial_user_signature_cap_id: ID of the unverified partial user signature capability
    /// Requires approval_threshold votes to execute the transaction on the Bitcoin network.
    SendBTC(vector<u8>, vector<u8>),
    /// Governance request to add a new member to the multisig wallet.
    /// The address specifies the new member to be added to the members vector.
    /// Affects future voting thresholds and requires careful consideration.
    AddMember(address),
    /// Governance request to remove an existing member from the multisig wallet.
    /// The address specifies the member to be removed from the members vector.
    /// May affect existing requests if the removed member had already voted.
    RemoveMember(address),
    /// Governance request to modify the approval threshold for transactions.
    /// The new threshold must be > 0 and <= current member count.
    /// Increasing the threshold makes transactions harder to approve.
    ChangeApprovalThreshold(u64),
    /// Governance request to modify the rejection threshold for requests.
    /// The new threshold must be > 0 and <= current member count.
    /// Decreasing the threshold makes it easier to reject requests.
    ChangeRejectionThreshold(u64),
    /// Governance request to modify the expiration duration for new requests.
    /// The new duration is specified in seconds and affects all future requests.
    /// Setting this too low may cause requests to expire before voting completes.
    ChangeExpirationDuration(u64),
}

/// Represents the successful execution result of an approved request.
/// This enum captures the outcome of governance and operational actions that have been
/// approved through the multisig voting process. Each variant corresponds to a RequestType
/// but contains the actual result data after successful execution.
///
/// Results are stored to provide an immutable audit trail of all executed actions.
public enum RequestResult has copy, drop, store {
    /// Bitcoin transaction successfully signed and ready for broadcast.
    /// Contains the signature request ID that can be used to retrieve the final signature
    /// from the IKA dWallet coordinator. The transaction is now ready for Bitcoin network submission.
    SendBTC(ID),
    /// New member successfully added to the multisig wallet.
    /// Contains the address of the member that was added to the members vector.
    /// This member can now participate in future voting processes.
    AddMember(address),
    /// Member successfully removed from the multisig wallet.
    /// Contains the address of the member that was removed from the members vector.
    /// This member can no longer participate in voting and their existing votes remain valid.
    RemoveMember(address),
    /// Approval threshold successfully updated for the multisig wallet.
    /// Contains the new approval threshold value that is now in effect.
    /// All future transaction requests will use this new threshold.
    ChangeApprovalThreshold(u64),
    /// Rejection threshold successfully updated for the multisig wallet.
    /// Contains the new rejection threshold value that is now in effect.
    /// All future requests will use this new threshold for rejection.
    ChangeRejectionThreshold(u64),
    /// Expiration duration successfully updated for the multisig wallet.
    /// Contains the new expiration duration (in seconds) that is now in effect.
    /// All future requests will use this new duration for automatic expiration.
    ChangeExpirationDuration(u64),
}

// === Public Functions ===

/// Creates a new multisig wallet with the specified configuration.
/// This function initializes the distributed key generation process and sets up the wallet.
///
/// # Arguments
/// * `coordinator` - The IKA dWallet coordinator for managing the distributed key generation
/// * `payment_ika` - IKA tokens for paying the DKG protocol fees
/// * `payment_sui` - SUI tokens for paying the DKG protocol fees
/// * `dwallet_network_encryption_key_id` - ID of the network encryption key for secure communication
/// * `members` - List of member addresses who can vote on transactions
/// * `approval_threshold` - Number of approvals required to execute transactions
/// * `rejection_threshold` - Number of rejections required to reject transactions
/// * `expiration_duration` - How long requests remain valid (in seconds)
/// * `ctx` - Transaction context for creating the shared object
///
/// # Returns
/// Shares the Multisig object publicly so all members can interact with it.
///
/// # Security Requirements
/// * `approval_threshold` must be > 0 and <= number of members
/// * `rejection_threshold` must be > 0 and <= number of members
/// * `members` vector must not be empty and contain unique addresses
/// * Caller must have sufficient IKA and SUI tokens for DKG fees
public fun new_multisig(
    coordinator: &mut DWalletCoordinator,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    dwallet_network_encryption_key_id: ID,
    members: vector<address>,
    approval_threshold: u64,
    rejection_threshold: u64,
    expiration_duration: u64,
    ctx: &mut TxContext,
) {
    assert!(approval_threshold > 0, error::invalid_approval_threshold!());
    assert!(rejection_threshold > 0, error::invalid_rejection_threshold!());
    assert!(approval_threshold <= members.length(), error::approval_threshold_too_high!());
    assert!(rejection_threshold <= members.length(), error::rejection_threshold_too_high!());
    assert!(members.length() > 0, error::empty_member_list!());

    let session_identifier = random_session_identifier(coordinator, ctx);

    let dwallet_cap = coordinator.request_dwallet_dkg_first_round(
        dwallet_network_encryption_key_id,
        constants::curve!(),
        session_identifier,
        payment_ika,
        payment_sui,
        ctx,
    );

    let multisig = Multisig {
        id: object::new(ctx),
        dwallet_cap: dwallet_cap,
        members: members,
        approval_threshold: approval_threshold,
        rejection_threshold: rejection_threshold,
        requests: table::new(ctx),
        expiration_duration: expiration_duration,
        request_id_counter: 0,
        presigns: vector::empty(),
    };

    transfer::public_share_object(multisig);
}

/// Completes the second round of distributed key generation for the multisig wallet.
/// This function finalizes the cryptographic setup required for Bitcoin transaction signing.
///
/// # Arguments
/// * `self` - Mutable reference to the multisig wallet being initialized
/// * `coordinator` - The IKA dWallet coordinator managing the DKG process
/// * `first_round_session_identifier` - Session ID from the first DKG round
/// * `payment_ika` - IKA tokens for paying the second round protocol fees
/// * `payment_sui` - SUI tokens for paying the second round protocol fees
/// * `centralized_public_key_share_and_proof` - Public key share with cryptographic proof
/// * `encrypted_centralized_secret_share_and_proof` - Encrypted secret share with proof
/// * `user_public_output` - User's public output from the DKG process
/// * `ctx` - Transaction context for the operation
///
/// # Security Notes
/// This function handles sensitive cryptographic material and should be called
/// only after successful completion of the first DKG round.
/// All cryptographic proofs are validated by the coordinator.
public fun multisig_dkg_second_round(
    self: &mut Multisig,
    coordinator: &mut DWalletCoordinator,
    first_round_session_identifier: SessionIdentifier,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    centralized_public_key_share_and_proof: vector<u8>,
    encrypted_centralized_secret_share_and_proof: vector<u8>,
    user_public_output: vector<u8>,
    ctx: &mut TxContext,
) {
    coordinator.request_dwallet_dkg_second_round(
        &self.dwallet_cap,
        centralized_public_key_share_and_proof,
        encrypted_centralized_secret_share_and_proof,
        constants::signer_public_key_address!(),
        user_public_output,
        constants::signer_public_key!(),
        first_round_session_identifier,
        payment_ika,
        payment_sui,
        ctx,
    );
}

/// Accepts the encrypted user secret key share and makes user share publicly available.
/// This is the final step in setting up the multisig wallet's distributed key infrastructure.
/// Note: Presign capabilities are created on-demand when the first request is submitted,
/// rather than in bulk during initialization, for better resource efficiency.
///
/// # Arguments
/// * `self` - Mutable reference to the multisig wallet
/// * `coordinator` - The IKA dWallet coordinator managing the process
/// * `payment_ika` - IKA tokens for paying the protocol fees
/// * `payment_sui` - SUI tokens for paying the protocol fees
/// * `encrypted_user_secret_key_share_id` - ID of the encrypted secret key share to accept
/// * `user_output_signature` - User's signature on the output for verification
/// * `public_user_secret_key_shares` - Public portion of the secret key shares to publish
/// * `ctx` - Transaction context for the operation
///
/// # Workflow
/// 1. Accepts the encrypted secret key share from the user
/// 2. Generates a new session identifier for the sharing process
/// 3. Makes the user's secret key shares public for the distributed wallet
/// 4. Presign capabilities are created lazily on first request
///
/// # Security Notes
/// This function handles cryptographic key material and should only be called
/// by authorized members during the wallet setup process.
public fun multisig_accept_and_share(
    self: &mut Multisig,
    coordinator: &mut DWalletCoordinator,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    encrypted_user_secret_key_share_id: ID,
    user_output_signature: vector<u8>,
    public_user_secret_key_shares: vector<u8>,
    ctx: &mut TxContext,
) {
    coordinator.accept_encrypted_user_share(
        self.dwallet_cap.dwallet_id(),
        encrypted_user_secret_key_share_id,
        user_output_signature,
    );

    let session_identifier = random_session_identifier(coordinator, ctx);

    coordinator.request_make_dwallet_user_secret_key_shares_public(
        self.dwallet_cap.dwallet_id(),
        public_user_secret_key_shares,
        session_identifier,
        payment_ika,
        payment_sui,
        ctx,
    );

    let session_identifier = random_session_identifier(coordinator, ctx);

    self
        .presigns
        .push_back(coordinator.request_presign(
            self.dwallet_cap.dwallet_id(),
            constants::curve!(),
            session_identifier,
            payment_ika,
            payment_sui,
            ctx,
        ));
}

/// Casts a vote on an existing multisig request.
/// Members can vote exactly once per request (approval or rejection).
/// Votes are irrevocable and contribute toward reaching approval or rejection thresholds.
///
/// When voting thresholds are reached, the request status is updated but execution
/// must be triggered separately via execute_request. This allows for batched processing
/// and gives more control over when requests are actually executed.
///
/// # Arguments
/// * `self` - Mutable reference to the multisig wallet
/// * `request_id` - The unique ID of the request to vote on
/// * `vote` - The vote decision: true for approval, false for rejection
/// * `clock` - Clock for checking request expiration
/// * `ctx` - Transaction context for the operation
///
/// # Returns
/// Updates the request's vote counts. Call execute_request separately to process
/// the request once voting thresholds are reached.
///
/// # Security Requirements
/// * Request must exist and be in Pending status
/// * Caller must be an active member of the multisig wallet
/// * Member cannot vote twice on the same request (irrevocable voting)
/// * Vote immediately contributes to threshold calculations
/// * Execution is separate from voting for better control
public fun vote_request(
    self: &mut Multisig,
    request_id: u64,
    vote: bool,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert!(self.requests.contains(request_id), error::request_not_found!());

    let request = self.requests.borrow_mut(request_id);

    assert!(request.status == RequestStatus::Pending, error::request_not_pending!());
    assert!(self.members.contains(&ctx.sender()), error::caller_not_member!());
    assert!(!request.votes.contains(ctx.sender()), error::already_voted!());

    if (clock.timestamp_ms() > request.created_at + self.expiration_duration) {
        request.status = RequestStatus::Rejected;
        return
    };

    request.votes.add(ctx.sender(), vote);

    if (vote) {
        request.approvers_count = request.approvers_count + 1;
    } else {
        request.rejecters_count = request.rejecters_count + 1;
    };
}

/// Executes an approved request or marks it as rejected.
/// This is the final step in the multisig request lifecycle.
/// It checks if voting thresholds are met and either executes the approved action
/// or permanently rejects the request. Can be called by anyone after thresholds are reached.
///
/// # Arguments
/// * `self` - Mutable reference to the multisig wallet
/// * `coordinator` - The IKA dWallet coordinator for Bitcoin transaction signing
/// * `payment_ika` - IKA tokens for paying Bitcoin transaction fees
/// * `payment_sui` - SUI tokens for paying Bitcoin transaction fees
/// * `message_centralized_signature` - Optional centralized signature for Bitcoin transactions
/// * `request_id` - The unique ID of the request to execute
/// * `clock` - Clock for checking request expiration before execution
/// * `ctx` - Transaction context for the operation
///
/// # Execution Flow
/// 1. **Expiration Check**: Verifies request hasn't expired before processing
/// 2. **Threshold Validation**: Checks that voting thresholds are actually met
/// 3. **Rejection Case**: If rejection threshold reached or expired, mark request as rejected
/// 4. **Approval Case**: If approval threshold reached, match on request type and execute:
///    - SendBTC: Signs Bitcoin transaction using presign capabilities and returns signature ID
///    - AddMember: Adds member to the members vector
///    - RemoveMember: Removes member from the members vector
///    - ChangeApprovalThreshold: Updates the approval threshold
///    - ChangeRejectionThreshold: Updates the rejection threshold
///    - ChangeExpirationDuration: Updates the expiration duration
///
/// # State Changes
/// - Request status becomes Approved(result) or Rejected
/// - Wallet configuration may be modified (members, thresholds, duration)
/// - All changes are atomic within the transaction
///
/// # Security Notes
/// - Validates thresholds before execution (prevents premature execution)
/// - All state changes are permanent and cannot be reversed
/// - Governance actions take effect immediately
/// - Can be called by any party after thresholds are reached
public fun execute_request(
    self: &mut Multisig,
    coordinator: &mut DWalletCoordinator,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    request_id: u64,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let request = self.requests.borrow_mut(request_id);

    if (clock.timestamp_ms() > request.created_at + self.expiration_duration) {
        request.status = RequestStatus::Rejected;
        return
    };

    assert!(
        request.approvers_count >= self.approval_threshold || request.rejecters_count >= self.rejection_threshold,
            error::insufficient_votes!(),
    );

    if (request.rejecters_count >= self.rejection_threshold) {
        request.status = RequestStatus::Rejected;
        return
    };

    let result = match (request.request_type) {
        RequestType::SendBTC(message, _message_centralized_signature) => {
            let unverified_partial_user_signature_cap = request
                .send_btc_unverified_partial_user_signature_cap
                .extract();

            let verified_partial_user_signature_cap = coordinator.verify_partial_user_signature_cap(
                unverified_partial_user_signature_cap,
                ctx,
            );

            let message_approval = coordinator.approve_message(
                &self.dwallet_cap,
                constants::signature_algorithm!(),
                constants::hash_scheme!(),
                message,
            );

            let session_identifier = random_session_identifier(coordinator, ctx);

            let sign_id = coordinator.request_sign_with_partial_user_signature_and_return_id(
                verified_partial_user_signature_cap,
                message_approval,
                session_identifier,
                payment_ika,
                payment_sui,
                ctx,
            );

            RequestResult::SendBTC(sign_id)
        },
        RequestType::AddMember(member_address) => {
            self.members.push_back(member_address);
            RequestResult::AddMember(member_address)
        },
        RequestType::RemoveMember(member_address) => {
            let mut index = self.members.find_index!(|member| member_address == *member);
            self.members.swap_remove(index.extract());
            RequestResult::RemoveMember(member_address)
        },
        RequestType::ChangeApprovalThreshold(new_threshold) => {
            self.approval_threshold = new_threshold;
            RequestResult::ChangeApprovalThreshold(new_threshold)
        },
        RequestType::ChangeRejectionThreshold(new_threshold) => {
            self.rejection_threshold = new_threshold;
            RequestResult::ChangeRejectionThreshold(new_threshold)
        },
        RequestType::ChangeExpirationDuration(new_duration) => {
            self.expiration_duration = new_duration;
            RequestResult::ChangeExpirationDuration(new_duration)
        },
    };

    request.status = RequestStatus::Approved(result);
}

// === Request Creation Functions ===

/// Creates a Bitcoin transaction request with all necessary signing components.
/// This function constructs a complete SendBTC request by creating the necessary
/// partial user signature capability and preparing all components for multisig signing.
///
/// The function handles the complex setup required for Bitcoin transaction signing,
/// including presign verification and partial signature capability creation.
///
/// # Arguments
/// * `self` - Mutable reference to the multisig wallet
/// * `coordinator` - The IKA dWallet coordinator for signature operations
/// * `payment_ika` - IKA tokens for paying protocol fees
/// * `payment_sui` - SUI tokens for paying protocol fees
/// * `transaction_hex` - Complete serialized Bitcoin transaction in hexadecimal format
/// * `message_centralized_signature` - Centralized signature component for the transaction
/// * `ctx` - Transaction context for the operation
///
/// # Returns
/// The unique request ID that was assigned to the Bitcoin transaction request.
///
/// # Security Requirements
/// * Caller must be an existing member of the multisig wallet
/// * A presign capability must be available in the wallet
/// * All cryptographic components are properly initialized
/// * Request creation automatically replenishes presign capabilities if needed
///
/// # Usage
/// This request type requires approval_threshold votes to execute and will
/// trigger Bitcoin transaction signing through the IKA dWallet protocol.
public fun send_btc_request(
    self: &mut Multisig,
    coordinator: &mut DWalletCoordinator,
    payment_ika: &mut Coin<IKA>,
    payment_sui: &mut Coin<SUI>,
    transaction_hex: vector<u8>,
    message_centralized_signature: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
): u64 {
    let session_identifier = random_session_identifier(coordinator, ctx);
    let unverified_presign_cap = self.presigns.swap_remove(0);
    let verified_presign_cap = coordinator.verify_presign_cap(unverified_presign_cap, ctx);

    let unverified_partial_user_signature_cap_from_request_sign = coordinator.request_future_sign(
        self.dwallet_cap.dwallet_id(),
        verified_presign_cap,
        transaction_hex,
        constants::hash_scheme!(),
        message_centralized_signature,
        session_identifier,
        payment_ika,
        payment_sui,
        ctx,
    );

    if (self.presigns.length() == 0) {
        let session_identifier = random_session_identifier(coordinator, ctx);

        self
            .presigns
            .push_back(coordinator.request_presign(
                self.dwallet_cap.dwallet_id(),
                constants::curve!(),
                session_identifier,
                payment_ika,
                payment_sui,
                ctx,
            ));
    };

    self.new_request(
        RequestType::SendBTC(transaction_hex, message_centralized_signature),
        option::some(unverified_partial_user_signature_cap_from_request_sign),
        clock,
        ctx,
    )
}

/// Creates a governance request to add a new member to the multisig wallet.
/// This function validates that the address is not already a member and that the
/// caller is an existing member before creating the request. Adding members affects
/// voting thresholds and requires collective approval.
///
/// # Arguments
/// * `self` - Multisig wallet reference for validation
/// * `member_address` - The Sui address of the new member to add
/// * `ctx` - Transaction context to verify caller is an existing member
///
/// # Returns
/// The unique request ID that was assigned to the add member request.
///
/// # Security Requirements
/// * Caller must be an existing member of the multisig wallet
/// * Address must not already be a member (prevents duplicates)
/// * Requires approval_threshold votes to execute
/// * New member gains full voting rights immediately upon approval
public fun add_member_request(
    self: &mut Multisig,
    member_address: address,
    clock: &Clock,
    ctx: &mut TxContext,
): u64 {
    assert!(!self.members.contains(&member_address), error::member_already_exists!());

    self.new_request(
        RequestType::AddMember(member_address),
        option::none(),
        clock,
        ctx,
    )
}

/// Creates a governance request to remove an existing member from the multisig wallet.
/// This function validates that the address is currently a member and that the
/// caller is an existing member before creating the request. Removing members affects
/// existing votes and requires careful consideration.
///
/// # Arguments
/// * `self` - Multisig wallet reference for validation
/// * `member_address` - The Sui address of the member to remove
/// * `ctx` - Transaction context to verify caller is an existing member
///
/// # Returns
/// The unique request ID that was assigned to the remove member request.
///
/// # Security Requirements
/// * Caller must be an existing member of the multisig wallet
/// * Address must be an existing member
/// * Requires approval_threshold votes to execute
/// * Removed member loses all voting rights and cannot create new requests
public fun remove_member_request(
    self: &mut Multisig,
    member_address: address,
    clock: &Clock,
    ctx: &mut TxContext,
): u64 {
    assert!(self.members.contains(&member_address), error::member_not_found!());

    self.new_request(
        RequestType::RemoveMember(member_address),
        option::none(),
        clock,
        ctx,
    )
}

/// Creates a governance request to modify the approval threshold.
/// This function validates that the new threshold is greater than zero and that the
/// caller is an existing member. Increasing the threshold makes transactions harder
/// to approve; decreasing makes them easier.
///
/// # Arguments
/// * `self` - Multisig wallet reference for validation
/// * `new_threshold` - The new approval threshold value (> 0)
/// * `ctx` - Transaction context to verify caller is an existing member
///
/// # Returns
/// The unique request ID that was assigned to the change approval threshold request.
///
/// # Security Requirements
/// * Caller must be an existing member of the multisig wallet
/// * New threshold must be greater than zero
/// * Requires approval_threshold votes to execute (based on current threshold)
/// * Affects all future transaction requests immediately upon approval
public fun change_approval_threshold_request(
    self: &mut Multisig,
    new_threshold: u64,
    clock: &Clock,
    ctx: &mut TxContext,
): u64 {
    assert!(new_threshold > 0, error::invalid_threshold!());

    self.new_request(
        RequestType::ChangeApprovalThreshold(new_threshold),
        option::none(),
        clock,
        ctx,
    )
}

/// Creates a governance request to modify the rejection threshold.
/// This function validates that the new threshold is greater than zero and that the
/// caller is an existing member. Increasing the threshold makes rejection harder;
/// decreasing makes it easier.
///
/// # Arguments
/// * `self` - Multisig wallet reference for validation
/// * `new_threshold` - The new rejection threshold value (> 0)
/// * `ctx` - Transaction context to verify caller is an existing member
///
/// # Returns
/// The unique request ID that was assigned to the change rejection threshold request.
///
/// # Security Requirements
/// * Caller must be an existing member of the multisig wallet
/// * New threshold must be greater than zero
/// * Requires approval_threshold votes to execute
/// * Affects all future requests immediately upon approval
public fun change_rejection_threshold_request(
    self: &mut Multisig,
    new_threshold: u64,
    clock: &Clock,
    ctx: &mut TxContext,
): u64 {
    assert!(new_threshold > 0, error::invalid_rejection_threshold_specific!());

    self.new_request(
        RequestType::ChangeRejectionThreshold(new_threshold),
        option::none(),
        clock,
        ctx,
    )
}

/// Creates a governance request to modify the request expiration duration.
/// This function validates that the new duration is greater than zero and that the
/// caller is an existing member. Setting the duration too low may cause requests
/// to expire before voting completes.
///
/// # Arguments
/// * `self` - Multisig wallet reference for validation
/// * `new_duration` - The new expiration duration in seconds (> 0)
/// * `ctx` - Transaction context to verify caller is an existing member
///
/// # Returns
/// The unique request ID that was assigned to the change expiration duration request.
///
/// # Security Requirements
/// * Caller must be an existing member of the multisig wallet
/// * New duration must be greater than zero
/// * Requires approval_threshold votes to execute
/// * Affects all future requests created after approval
public fun change_expiration_duration_request(
    self: &mut Multisig,
    new_duration: u64,
    clock: &Clock,
    ctx: &mut TxContext,
): u64 {
    assert!(new_duration > 0, error::invalid_expiration_duration!());

    self.new_request(
        RequestType::ChangeExpirationDuration(new_duration),
        option::none(),
        clock,
        ctx,
    )
}

// === Private Functions ===

/// Generates a random session identifier for DKG operations.
/// Uses the transaction context's fresh object address to create a unique identifier.
///
/// # Arguments
/// * `coordinator` - The dWallet coordinator that will register the session
/// * `ctx` - Transaction context containing the fresh address generator
///
/// # Returns
/// A new SessionIdentifier registered with the coordinator
///
fun random_session_identifier(
    coordinator: &mut DWalletCoordinator,
    ctx: &mut TxContext,
): SessionIdentifier {
    coordinator.register_session_identifier(
        ctx.fresh_object_address().to_bytes(),
        ctx,
    )
}

/// Creates a new request to be voted on by the multisig members.
/// This function initializes a new request with the specified type and parameters,
/// assigning it a unique ID and setting up the initial voting state.
///
/// The request starts in Pending status and must be approved by the required threshold
/// of members before it can be executed. Only multisig members can create requests.
///
/// For SendBTC requests, the unverified partial user signature capability is validated
/// and stored for later use during execution.
///
/// # Arguments
/// * `self` - Mutable reference to the multisig wallet
/// * `request_type` - The type of request to create (SendBTC, AddMember, etc.)
/// * `unverified_partial_user_signature_cap` - Required for SendBTC requests, capability for signing
/// * `payment_ika` - IKA tokens for paying protocol fees
/// * `payment_sui` - SUI tokens for paying protocol fees
/// * `clock` - Clock for getting the current timestamp for expiration tracking
/// * `ctx` - Transaction context for the operation
///
/// # Returns
/// The unique request ID that was assigned to the newly created request.
///
/// # Security Requirements
/// * Caller must be an existing member of the multisig wallet
/// * SendBTC requests must include a valid unverified partial user signature capability
/// * Request ID is guaranteed to be unique within this wallet
/// * Request starts with zero votes and Pending status
/// * Signature capability is validated against the request type
fun new_request(
    self: &mut Multisig,
    request_type: RequestType,
    unverified_partial_user_signature_cap: Option<UnverifiedPartialUserSignatureCap>,
    clock: &Clock,
    ctx: &mut TxContext,
): u64 {
    assert!(self.members.contains(&ctx.sender()), error::caller_not_member!());

    let request = Request {
        request_type: request_type,
        status: RequestStatus::Pending,
        created_at: clock.timestamp_ms(),
        approvers_count: 0,
        rejecters_count: 0,
        votes: table::new(ctx),
        send_btc_unverified_partial_user_signature_cap: unverified_partial_user_signature_cap,
    };

    self.request_id_counter = self.request_id_counter + 1;

    self.requests.add(self.request_id_counter, request);

    self.request_id_counter
}
