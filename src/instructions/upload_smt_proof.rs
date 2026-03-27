//! UploadSmtProof instruction (TX2 of 3-TX withdraw)
//!
//! Uploads SMT proof, verifies it, and stores new_smt_root + key_image

use pinocchio::{
    account_info::AccountInfo,
    pubkey::{self, Pubkey},
    ProgramResult,
};
use pinocchio_log::log;

use crate::error::RdpError;
use crate::state::{RingPool, PendingWithdraw, PENDING_SEED};
use crate::crypto::sparse_merkle::{SmtProof, verify_and_insert};

/// Process upload SMT proof instruction
///
/// Layout:
/// - key_image: 32 bytes
/// - smt_siblings: 20 * 32 = 640 bytes
/// - smt_leaf_index: 4 bytes
/// - pending_bump: 1 byte
///
/// Accounts:
/// 0. `[]` Ring pool account (for SMT root verification)
/// 1. `[writable]` PendingWithdraw PDA
/// 2. `[signer]` Creator (must match PDA creator)
pub fn process_upload_smt_proof(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(RdpError::MissingAccount.into());
    }

    let ring_pool_info = &accounts[0];
    let pending_info = &accounts[1];
    let creator_info = &accounts[2];

    // Creator must be signer
    if !creator_info.is_signer() {
        return Err(RdpError::MissingAccount.into());
    }

    // Verify ownerships
    if ring_pool_info.owner() != program_id {
        return Err(RdpError::InvalidAccountOwner.into());
    }
    if pending_info.owner() != program_id {
        return Err(RdpError::InvalidAccountOwner.into());
    }

    // Parse instruction data
    // Layout: key_image(32) + smt_proof(644) + pending_bump(1) = 677 bytes
    let expected_len = 32 + SmtProof::SIZE + 1;
    if data.len() < expected_len {
        return Err(RdpError::InvalidInstructionData.into());
    }

    // Parse key_image
    let mut key_image = [0u8; 32];
    key_image.copy_from_slice(&data[0..32]);

    // Parse SMT proof
    let smt_proof = SmtProof::from_bytes(&data[32..32 + SmtProof::SIZE])
        .ok_or(RdpError::InvalidInstructionData)?;

    let pending_bump = data[32 + SmtProof::SIZE];

    // Read pending data to verify creator and ring_pool
    let creator;
    let ring_pool_key;
    {
        let pending_data = pending_info.try_borrow_data()?;
        let pending = PendingWithdraw::from_bytes(&pending_data)?;

        // Verify creator
        if pending.creator != *creator_info.key().as_ref() {
            return Err(RdpError::InvalidAccountOwner.into());
        }

        // Verify ring_pool matches
        if pending.ring_pool != *ring_pool_info.key().as_ref() {
            return Err(RdpError::InvalidPDA.into());
        }

        creator = pending.creator;
        ring_pool_key = pending.ring_pool;
    }

    // Verify pending PDA
    let bump_slice = [pending_bump];
    let pending_seeds: &[&[u8]] = &[
        PENDING_SEED,
        ring_pool_info.key().as_ref(),
        creator_info.key().as_ref(),
        &bump_slice,
    ];

    let expected_pda = pubkey::create_program_address(pending_seeds, program_id)?;
    if pending_info.key() != &expected_pda {
        return Err(RdpError::InvalidPDA.into());
    }

    // Verify SMT proof against current pool root
    let new_smt_root = {
        let pool_data = ring_pool_info.try_borrow_data()?;
        let pool = RingPool::from_bytes(&pool_data)?;

        verify_and_insert(
            pool.get_smt_root(),
            &key_image,
            &smt_proof,
        ).map_err(|_| RdpError::KeyImageAlreadySpent)?
    };

    // Store verified result
    {
        let mut pending_data = pending_info.try_borrow_mut_data()?;
        let pending = PendingWithdraw::from_bytes_mut(&mut pending_data)?;
        pending.store_smt_result(&new_smt_root, &key_image)?;
    }

    log!("UploadSmtProof: verified");

    Ok(())
}
