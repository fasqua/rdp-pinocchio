//! Deposit instruction for Ring Diffusion Protocol
//!
//! Deposits SOL into the pool vault with a Pedersen commitment

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::{self, Pubkey},
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use pinocchio_log::log;

use crate::error::{RdpError, RdpResult};
use crate::state::{RingPool, COMMITMENT_SIZE, VAULT_SEED};
use crate::crypto::{verify_bulletproof, BulletproofData};

/// Deposit instruction data layout
pub struct DepositData {
    pub commitment: [u8; COMMITMENT_SIZE],
    pub bulletproof: BulletproofData,
}

impl DepositData {
    pub const MIN_SIZE: usize = COMMITMENT_SIZE;

    pub fn from_bytes(data: &[u8]) -> RdpResult<Self> {
        if data.len() < Self::MIN_SIZE {
            return Err(RdpError::InvalidInstructionData.into());
        }

        let mut commitment = [0u8; COMMITMENT_SIZE];
        commitment.copy_from_slice(&data[0..COMMITMENT_SIZE]);

        let bulletproof = BulletproofData::from_bytes(&data[COMMITMENT_SIZE..])?;

        Ok(Self {
            commitment,
            bulletproof,
        })
    }
}

/// Process deposit instruction
///
/// Accounts:
/// 0. `[writable]` Ring pool account (state)
/// 1. `[writable]` Vault PDA (holds SOL)
/// 2. `[writable, signer]` Depositor account
/// 3. `[]` System program
/// 4. `[]` Clock sysvar
pub fn process_deposit(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 5 {
        return Err(RdpError::MissingAccount.into());
    }

    let ring_pool_info = &accounts[0];
    let vault_info = &accounts[1];
    let depositor_info = &accounts[2];
    let system_program_info = &accounts[3];
    let _clock_info = &accounts[4];

    // Verify depositor is signer
    if !depositor_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify ring pool is owned by our program
    if ring_pool_info.owner() != program_id {
        return Err(RdpError::InvalidAccountOwner.into());
    }

    // Parse instruction data
    let deposit_data = DepositData::from_bytes(data)?;

    // Verify bulletproof (range proof)
    verify_bulletproof(&deposit_data.bulletproof)?;

    // Get clock for timestamp
    let clock = Clock::get()?;
    let timestamp = clock.unix_timestamp as u64;

    // Read pool data to get denomination and vault_bump
    let (denomination, vault_bump) = {
        let pool_data = ring_pool_info.try_borrow_data()?;
        let pool = RingPool::from_bytes(&pool_data)?;
        
        if pool.is_full() {
            return Err(RdpError::PoolFull.into());
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

    // Check depositor has enough lamports
    if depositor_info.lamports() < denomination {
        return Err(ProgramError::InsufficientFunds);
    }

    // Transfer SOL: depositor -> vault using System Program CPI
    {
        let mut transfer_data = [0u8; 12];
        transfer_data[0..4].copy_from_slice(&2u32.to_le_bytes()); // Transfer instruction = 2
        transfer_data[4..12].copy_from_slice(&denomination.to_le_bytes());

        let transfer_accounts = [
            pinocchio::instruction::AccountMeta {
                pubkey: depositor_info.key(),
                is_signer: true,
                is_writable: true,
            },
            pinocchio::instruction::AccountMeta {
                pubkey: vault_info.key(),
                is_signer: false,
                is_writable: true,
            },
        ];

        let transfer_ix = pinocchio::instruction::Instruction {
            program_id: system_program_info.key(),
            accounts: &transfer_accounts,
            data: &transfer_data,
        };

        pinocchio::program::invoke(
            &transfer_ix,
            &[depositor_info, vault_info],
        )?;
    }

    // Add commitment to pool
    {
        let mut pool_data = ring_pool_info.try_borrow_mut_data()?;
        let pool = RingPool::from_bytes_mut(&mut pool_data)?;
        let _index = pool.add_commitment(&deposit_data.commitment, timestamp)?;
    }

    log!("Deposit complete");

    Ok(())
}
