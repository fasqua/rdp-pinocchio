//! ExecuteWithdraw instruction (TX2 of 2-TX withdraw)
//!
//! Verifies ring signature using stored ring pubkeys, transfers SOL, closes PDA

use pinocchio::{
    account_info::AccountInfo,
    pubkey::{self, Pubkey},
    instruction::{Seed, Signer},
    ProgramResult,
};
use pinocchio_log::log;

use crate::error::RdpError;
use crate::state::{RingPool, PendingWithdraw, VAULT_SEED, PENDING_SEED};
use crate::crypto::{verify_ring_signature, RingSignatureData, MAX_RING_SIZE};

/// Process execute withdraw instruction
///
/// Layout:
/// - signature_c: 32 bytes
/// - responses: ring_size * 32 bytes (from pending state)
/// - key_image: 32 bytes
/// - pending_bump: 1 byte
///
/// Accounts:
/// 0. `[writable]` Ring pool account
/// 1. `[writable]` Vault PDA
/// 2. `[writable]` Destination
/// 3. `[writable]` PendingWithdraw PDA (to be closed)
/// 4. `[writable]` Creator (receives rent refund)
/// 5. `[]` System program
pub fn process_execute_withdraw(
    program_id: &Pubkey,
    accounts: &[AccountInfo],

    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 6 {
        return Err(RdpError::MissingAccount.into());
    }

    let ring_pool_info = &accounts[0];
    let vault_info = &accounts[1];
    let destination_info = &accounts[2];
    let pending_info = &accounts[3];
    let creator_info = &accounts[4];
    let system_program_info = &accounts[5];

    // Verify ownerships
    if ring_pool_info.owner() != program_id {
        return Err(RdpError::InvalidAccountOwner.into());
    }
    if pending_info.owner() != program_id {
        return Err(RdpError::InvalidAccountOwner.into());
    }

    // Read pending data
    let (ring_size, ring_pubkeys, destination, amount, creator, ring_pool_key) = {
        let pending_data = pending_info.try_borrow_data()?;
        let pending = PendingWithdraw::from_bytes(&pending_data)?;

        let rs = pending.ring_size as usize;
        let mut ring = [[0u8; 32]; MAX_RING_SIZE];
        for i in 0..rs {
            ring[i] = pending.ring_pubkeys[i];
        }

        (
            rs,
            ring,
            pending.destination,
            pending.amount,
            pending.creator,
            pending.ring_pool,
        )
    };

    // Verify ring pool matches
    if ring_pool_info.key().as_ref() != ring_pool_key.as_slice() {
        return Err(RdpError::InvalidPDA.into());
    }

    // Verify destination matches
    if destination_info.key().as_ref() != destination.as_slice() {
        return Err(RdpError::InvalidPDA.into());
    }

    // Verify creator matches
    if creator_info.key().as_ref() != creator.as_slice() {
        return Err(RdpError::InvalidPDA.into());
    }

    // Parse signature data
    // Layout: c(32) + responses(ring_size * 32) + key_image(32) + pending_bump(1)
    let expected_len = 32 + (ring_size * 32) + 32 + 1;
    if data.len() < expected_len {
        return Err(RdpError::InvalidInstructionData.into());
    }

    let mut offset = 0;

    let mut c = [0u8; 32];
    c.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    let mut responses = [[0u8; 32]; MAX_RING_SIZE];
    for i in 0..ring_size {
        responses[i].copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
    }

    let mut key_image = [0u8; 32];
    key_image.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    let pending_bump = data[offset];

    // Verify pending PDA
    let pending_bump_slice = [pending_bump];
    let pending_seeds: &[&[u8]] = &[
        PENDING_SEED,
        ring_pool_info.key().as_ref(),
        creator_info.key().as_ref(),
        &pending_bump_slice,
    ];
    let expected_pending = pubkey::create_program_address(pending_seeds, program_id)?;
    if pending_info.key() != &expected_pending {
        return Err(RdpError::InvalidPDA.into());
    }

    // Get vault bump and verify key image
    let vault_bump = {
        let pool_data = ring_pool_info.try_borrow_data()?;
        let pool = RingPool::from_bytes(&pool_data)?;

        if pool.is_key_image_spent(&key_image) {
            return Err(RdpError::KeyImageAlreadySpent.into());
        }

        pool.vault_bump
    };

    // Verify vault PDA
    let vault_bump_slice = [vault_bump];
    let vault_seeds: &[&[u8]] = &[
        VAULT_SEED,
        ring_pool_info.key().as_ref(),
        &vault_bump_slice,
    ];
    let expected_vault = pubkey::create_program_address(vault_seeds, program_id)?;
    if vault_info.key() != &expected_vault {
        return Err(RdpError::InvalidPDA.into());
    }

    // Construct message: destination (32) + amount (8) = 40 bytes
    let mut message = [0u8; 40];
    message[0..32].copy_from_slice(&destination);
    message[32..40].copy_from_slice(&amount.to_le_bytes());

    // Create signature data
    let ring_signature = RingSignatureData {
        c,
        responses,
        ring_size: ring_size as u8,
        key_image,
    };

    // Verify ring signature
    verify_ring_signature(&message, &ring_pubkeys[..ring_size], &ring_signature)?;

    // Record key image as spent
    {
        let mut pool_data = ring_pool_info.try_borrow_mut_data()?;
        let pool = RingPool::from_bytes_mut(&mut pool_data)?;
        pool.record_spent_key_image(&key_image)?;
    }

    // Transfer SOL from vault to destination
    {
        let mut transfer_data = [0u8; 12];
        transfer_data[0..4].copy_from_slice(&2u32.to_le_bytes());
        transfer_data[4..12].copy_from_slice(&amount.to_le_bytes());

        let transfer_accounts = [
            pinocchio::instruction::AccountMeta {
                pubkey: vault_info.key(),
                is_signer: true,
                is_writable: true,
            },
            pinocchio::instruction::AccountMeta {
                pubkey: destination_info.key(),
                is_signer: false,
                is_writable: true,
            },
        ];

        let transfer_ix = pinocchio::instruction::Instruction {
            program_id: system_program_info.key(),
            accounts: &transfer_accounts,
            data: &transfer_data,
        };

        let vault_seeds_arr: [Seed; 3] = [
            Seed::from(VAULT_SEED),
            Seed::from(ring_pool_info.key().as_ref()),
            Seed::from(vault_bump_slice.as_ref()),
        ];
        let vault_signer = Signer::from(&vault_seeds_arr);

        pinocchio::program::invoke_signed(
            &transfer_ix,
            &[vault_info, destination_info],
            &[vault_signer],
        )?;
    }

    // Close PendingWithdraw account - transfer lamports to creator
    {
        let pending_lamports = pending_info.lamports();
        
        // Decrease pending lamports to 0
        unsafe {
            *pending_info.borrow_mut_lamports_unchecked() = 0;
        }
        
        // Increase creator lamports
        unsafe {
            *creator_info.borrow_mut_lamports_unchecked() += pending_lamports;
        }

        // Zero out pending data
        let mut pending_data = pending_info.try_borrow_mut_data()?;
        pending_data.fill(0);
    }

    log!("ExecuteWithdraw: complete");

    Ok(())
}
