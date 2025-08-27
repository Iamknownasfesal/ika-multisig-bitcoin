// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_btc_multisig::multisig_events;

use ika_btc_multisig::event_wrapper::emit_event;
use ika_btc_multisig::multisig_request::RequestType;
use ika_btc_multisig::multisig_request::RequestStatus;

// === Event Structs ===

/// Event emitted when a new multisig wallet is successfully created.
/// This event marks the beginning of the multisig wallet lifecycle and includes
/// all the initial configuration parameters that define the wallet's behavior.
public struct MultisigCreated has drop, copy, store {
    /// Unique identifier of the newly created multisig wallet
    multisig_id: ID,
    /// Initial list of member addresses who can vote on requests
    members: vector<address>,
    /// Number of approvals required to execute requests
    approval_threshold: u64,
    /// Number of rejections required to definitively reject requests
    rejection_threshold: u64,
    /// Duration in milliseconds after which requests automatically expire
    expiration_duration: u64,
    /// Address of the user who created the multisig wallet
    created_by: address,
}

/// Event emitted when the second round of distributed key generation begins.
/// This event signals that the multisig wallet has progressed past the initial setup
/// and is now in the cryptographic key generation phase.
public struct MultisigDKGSecondRoundStarted has drop, copy, store {
    /// Unique identifier of the multisig wallet entering DKG second round
    multisig_id: ID,
}

/// Event emitted when the multisig wallet has successfully completed the DKG process
/// and is ready for use. This marks the transition from setup phase to operational phase.
public struct MultisigAcceptedAndShared has drop, copy, store {
    /// Unique identifier of the fully initialized multisig wallet
    multisig_id: ID,
}

/// Event emitted when a new request is created in the multisig wallet.
/// This event tracks all governance and operational actions that require multisig approval.
public struct RequestCreated has drop, copy, store {
    /// Unique identifier assigned to the newly created request
    request_id: u64,
    /// The type and details of the request (transaction, governance change, etc.)
    request_type: RequestType,
    /// Address of the member who created the request
    created_by: address,
}

/// Event emitted when a request is resolved (either approved and executed or rejected).
/// This event marks the completion of the multisig voting and execution process.
public struct RequestResolved has drop, copy, store {
    /// Unique identifier of the resolved request
    request_id: u64,
    /// Final status of the request (Approved with result or Rejected)
    request_status: RequestStatus,
}

// === Public(Package) Functions ===

/// Emits a MultisigCreated event when a new multisig wallet is initialized.
/// This function should be called immediately after successful wallet creation
/// to notify listeners about the new multisig wallet and its configuration.
///
/// # Arguments
/// * `multisig_id` - Unique identifier of the created multisig wallet
/// * `members` - Initial list of member addresses
/// * `approval_threshold` - Number of approvals required for request execution
/// * `rejection_threshold` - Number of rejections required for request rejection
/// * `expiration_duration` - Request expiration time in milliseconds
/// * `created_by` - Address of the user who created the wallet
public(package) fun multisig_created(
    multisig_id: ID,
    members: vector<address>,
    approval_threshold: u64,
    rejection_threshold: u64,
    expiration_duration: u64,
    created_by: address,
) {
    emit_event(MultisigCreated {
        multisig_id,
        members,
        approval_threshold,
        rejection_threshold,
        expiration_duration,
        created_by,
    });
}

/// Emits a MultisigDKGSecondRoundStarted event when DKG second round begins.
/// This function marks the transition from initial setup to cryptographic key generation.
/// Call this function when the multisig_dkg_second_round function is invoked.
///
/// # Arguments
/// * `multisig_id` - Unique identifier of the multisig wallet starting DKG second round
public(package) fun multisig_dkg_second_round_started(
    multisig_id: ID,
) {
    emit_event(MultisigDKGSecondRoundStarted {
        multisig_id,
    });
}

/// Emits a MultisigAcceptedAndShared event when DKG is completed and wallet is ready.
/// This function signals that the multisig wallet has successfully completed its
/// cryptographic setup and is now operational for creating and voting on requests.
///
/// # Arguments
/// * `multisig_id` - Unique identifier of the fully initialized multisig wallet
public(package) fun multisig_accepted_and_shared(
    multisig_id: ID,
) {
    emit_event(MultisigAcceptedAndShared {
        multisig_id,
    });
}

/// Emits a RequestCreated event when a new request is submitted to the multisig wallet.
/// This function should be called whenever a new request is created through any of the
/// request creation functions (transaction_request, add_member_request, etc.).
///
/// # Arguments
/// * `request_id` - Unique identifier assigned to the new request
/// * `request_type` - Type and details of the request being created
/// * `created_by` - Address of the member who created the request
public(package) fun request_created(
    request_id: u64,
    request_type: RequestType,
    created_by: address,
) {
    emit_event(RequestCreated {
        request_id,
        request_type,
        created_by,
    });
}

/// Emits a RequestResolved event when a request reaches final resolution.
/// This function should be called when a request is either approved and executed
/// or definitively rejected, marking the end of the request's lifecycle.
///
/// # Arguments
/// * `request_id` - Unique identifier of the resolved request
/// * `request_status` - Final status (Approved with result or Rejected)
public(package) fun request_resolved(
    request_id: u64,
    request_status: RequestStatus,
) {
    emit_event(RequestResolved {
        request_id,
        request_status,
    });
}