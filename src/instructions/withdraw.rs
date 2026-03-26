//! Withdraw instruction for Ring Diffusion Protocol
//!
//! Matches Anchor design:
//! - ring_pubkeys provided by client
//! - message = destination (32) + amount (8) = 40 bytes
//! - key_image tracked in pool state (simplified vs Anchor's separate PDA)

use pinocchio::{
    account_info::AccountInfo,
    pubkey::{self, Pubkey},
    instruction::{Seed, Signer},
    ProgramResult,
};
use pinocchio_log::log;

use crate::error::{RdpError, RdpResult};
use crate::state::{RingPool, VAULT_SEED};
use crate::crypto::{
    verify_ring_signature,
    RingSignatureData,
    POINT_SIZE,
    MAX_RING_SIZE,
};

/// Withdraw instruction data layout (matches Anchor)
///
/// Layout:
/// - ring_size: 1 byte
/// - ring_pubkeys: ring_size * 32 bytes
/// - signature_c: 32 bytes
/// - signature_responses: ring_size * 32 bytes
/// - key_image: 32 bytes
/// - amount: 8 bytes
/// - destination: 32 bytes (for message construction, actual destination is account)
pub struct WithdrawData {
    pub ring_pubkeys: [[u8; POINT_SIZE]; MAX_RING_SIZE],
    pub ring_size: u8,
    pub ring_signature: RingSignatureData,
    pub amount: u64,
}

impl WithdrawData {
    pub fn from_bytes(data: &[u8]) -> RdpResult<Self> {
        if data.len() < 2 {
            return Err(RdpError::InvalidInstructionData.into());
        }

        let mut offset = 0;

        // Read ring_size
        let ring_size = data[offset];
        offset += 1;

        if ring_size < 2 || ring_size > MAX_RING_SIZE as u8 {
            return Err(RdpError::RingSizeTooSmall.into());
        }

        let rs = ring_size as usize;

        // Check minimum data length
        // ring_pubkeys (rs*32) + c (32) + responses (rs*32) + key_image (32) + amount (8)
        let min_len = 1 + (rs * 32) + 32 + (rs * 32) + 32 + 8;
        if data.len() < min_len {
            return Err(RdpError::InvalidInstructionData.into());
        }

        // Read ring_pubkeys
        let mut ring_pubkeys = [[0u8; POINT_SIZE]; MAX_RING_SIZE];
        for i in 0..rs {
            ring_pubkeys[i].copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
        }

        // Read signature_c
        let mut c = [0u8; 32];
        c.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        // Read responses
        let mut responses = [[0u8; 32]; MAX_RING_SIZE];
        for i in 0..rs {
            responses[i].copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
        }

        // Read key_image
        let mut key_image = [0u8; 32];
        key_image.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        // Read amount
        let amount = u64::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]);

        let ring_signature = RingSignatureData {
            c,
            responses,
            ring_size,
            key_image,
        };

        Ok(Self {
            ring_pubkeys,
            ring_size,
            ring_signature,
            amount,
        })
    }
}

/// Process withdraw instruction
///
/// Accounts:
/// 0. `[writable]` Ring pool account (state)
/// 1. `[writable]` Vault PDA (holds SOL)
/// 2. `[writable]` Destination account
/// 3. `[]` System program
pub fn process_withdraw(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(RdpError::MissingAccount.into());
    }

    let ring_pool_info = &accounts[0];
    let vault_info = &accounts[1];
    let destination_info = &accounts[2];
    let system_program_info = &accounts[3];

    // Verify ring pool is owned by program
    if ring_pool_info.owner() != program_id {
        return Err(RdpError::InvalidAccountOwner.into());
    }

    // Parse instruction data
    let withdraw_data = WithdrawData::from_bytes(data)?;
    let ring_size = withdraw_data.ring_size as usize;

    // Read pool data and verify
    let (denomination, vault_bump) = {
        let pool_data = ring_pool_info.try_borrow_data()?;
        let pool = RingPool::from_bytes(&pool_data)?;

        // Check amount matches denomination
        if withdraw_data.amount != pool.denomination {
            return Err(RdpError::InvalidDenomination.into());
        }

        // Check key image not already spent
        if pool.is_key_image_spent(&withdraw_data.ring_signature.key_image) {
            return Err(RdpError::KeyImageAlreadySpent.into());
        }

        (pool.denomination, pool.vault_bump)
    };

    // Verify vault PDA
    let bump_slice = [vault_bump];
    let vault_seeds: &[&[u8]] = &[
        VAULT_SEED,
        ring_pool_info.key().as_ref(),
        &bump_slice,
    ];

    let expected_vault = pubkey::create_program_address(vault_seeds, program_id)?;

    if vault_info.key() != &expected_vault {
        return Err(RdpError::InvalidPDA.into());
    }

    // Construct message: destination (32) + amount (8) = 40 bytes
    let mut message = [0u8; 40];
    message[0..32].copy_from_slice(destination_info.key().as_ref());
    message[32..40].copy_from_slice(&withdraw_data.amount.to_le_bytes());

    // Verify ring signature
    verify_ring_signature(
        &message,
        &withdraw_data.ring_pubkeys[..ring_size],
        &withdraw_data.ring_signature,
    )?;

    // Record key image as spent
    {
        let mut pool_data = ring_pool_info.try_borrow_mut_data()?;
        let pool = RingPool::from_bytes_mut(&mut pool_data)?;
        pool.record_spent_key_image(&withdraw_data.ring_signature.key_image)?;
    }

    // Transfer SOL from vault to destination
    {
        let mut transfer_data = [0u8; 12];
        transfer_data[0..4].copy_from_slice(&2u32.to_le_bytes());
        transfer_data[4..12].copy_from_slice(&denomination.to_le_bytes());

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

        let seeds: [Seed; 3] = [
            Seed::from(VAULT_SEED),
            Seed::from(ring_pool_info.key().as_ref()),
            Seed::from(bump_slice.as_ref()),
        ];
        let vault_signer = Signer::from(&seeds);

        pinocchio::program::invoke_signed(
            &transfer_ix,
            &[vault_info, destination_info],
            &[vault_signer],
        )?;
    }

    log!("Withdraw complete");

    Ok(())
}
