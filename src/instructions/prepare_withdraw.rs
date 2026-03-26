//! PrepareWithdraw instruction (TX1 of 2-TX withdraw)
//!
//! Creates a PendingWithdraw PDA account containing ring pubkeys

use pinocchio::{
    account_info::AccountInfo,
    pubkey::{self, Pubkey},
    ProgramResult,
    sysvars::{rent::Rent, Sysvar},
};
use pinocchio_log::log;

use crate::error::RdpError;
use crate::state::{RingPool, PendingWithdraw, PENDING_SEED, MAX_RING_SIZE};

/// Process prepare withdraw instruction
///
/// Creates PendingWithdraw PDA: ["pending", ring_pool, creator]
///
/// Layout:
/// - ring_size: 1 byte
/// - ring_pubkeys: ring_size * 32 bytes
/// - destination: 32 bytes
/// - amount: 8 bytes
/// - bump: 1 byte
///
/// Accounts:
/// 0. `[writable]` Ring pool account
/// 1. `[writable]` PendingWithdraw PDA (to be created)
/// 2. `[signer, writable]` Creator/payer
/// 3. `[]` System program
pub fn process_prepare_withdraw(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(RdpError::MissingAccount.into());
    }

    let ring_pool_info = &accounts[0];
    let pending_info = &accounts[1];
    let creator_info = &accounts[2];
    let system_program_info = &accounts[3];

    // Verify ring pool ownership
    if ring_pool_info.owner() != program_id {
        return Err(RdpError::InvalidAccountOwner.into());
    }

    // Creator must be signer
    if !creator_info.is_signer() {
        return Err(RdpError::MissingAccount.into());
    }

    // Parse instruction data
    if data.is_empty() {
        return Err(RdpError::InvalidInstructionData.into());
    }

    let ring_size = data[0] as usize;
    
    if ring_size < 2 || ring_size > 16 {
        return Err(RdpError::RingSizeTooSmall.into());
    }

    // Expected: ring_size(1) + ring_pubkeys(N*32) + destination(32) + amount(8) + bump(1)
    let expected_len = 1 + (ring_size * 32) + 32 + 8 + 1;
    if data.len() < expected_len {
        return Err(RdpError::InvalidInstructionData.into());
    }

    // Parse ring pubkeys into fixed array
    let mut ring_pubkeys = [[0u8; 32]; MAX_RING_SIZE];
    let mut offset = 1;
    for i in 0..ring_size {
        ring_pubkeys[i].copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
    }

    // Parse destination
    let mut destination = [0u8; 32];
    destination.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    // Parse amount
    let amount = u64::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ]);
    offset += 8;

    // Parse bump
    let bump = data[offset];

    // Verify amount matches pool denomination
    {
        let pool_data = ring_pool_info.try_borrow_data()?;
        let pool = RingPool::from_bytes(&pool_data)?;
        if amount != pool.denomination {
            return Err(RdpError::InvalidDenomination.into());
        }
    }

    // Verify PDA
    let bump_slice = [bump];
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

    // Create PendingWithdraw account via CPI
    let space = PendingWithdraw::SIZE as u64;
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(space as usize);

    // Create account instruction data
    let mut create_account_data = [0u8; 52];
    create_account_data[0..4].copy_from_slice(&0u32.to_le_bytes()); // CreateAccount instruction
    create_account_data[4..12].copy_from_slice(&lamports.to_le_bytes());
    create_account_data[12..20].copy_from_slice(&space.to_le_bytes());
    create_account_data[20..52].copy_from_slice(program_id.as_ref());

    let create_accounts = [
        pinocchio::instruction::AccountMeta {
            pubkey: creator_info.key(),
            is_signer: true,
            is_writable: true,
        },
        pinocchio::instruction::AccountMeta {
            pubkey: pending_info.key(),
            is_signer: true,
            is_writable: true,
        },
    ];

    let create_ix = pinocchio::instruction::Instruction {
        program_id: system_program_info.key(),
        accounts: &create_accounts,
        data: &create_account_data,
    };

    // Create signer seeds for PDA
    let seeds: [pinocchio::instruction::Seed; 4] = [
        pinocchio::instruction::Seed::from(PENDING_SEED),
        pinocchio::instruction::Seed::from(ring_pool_info.key().as_ref()),
        pinocchio::instruction::Seed::from(creator_info.key().as_ref()),
        pinocchio::instruction::Seed::from(bump_slice.as_ref()),
    ];
    let pda_signer = pinocchio::instruction::Signer::from(&seeds);

    pinocchio::program::invoke_signed(
        &create_ix,
        &[creator_info, pending_info],
        &[pda_signer],
    )?;

    // Initialize PendingWithdraw data
    {
        let mut pending_data = pending_info.try_borrow_mut_data()?;
        PendingWithdraw::initialize(
            &mut pending_data,
            ring_pool_info.key().as_ref().try_into().unwrap(),
            &ring_pubkeys[..ring_size],
            &destination,
            amount,
            creator_info.key().as_ref().try_into().unwrap(),
        )?;
    }

    log!("PrepareWithdraw: ring={}", ring_size as u8);

    Ok(())
}
