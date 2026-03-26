//! Initialize Ring Pool instruction
//!
//! Creates a new ring pool with specified denomination
//! Pool uses separate vault PDA for holding SOL

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};
use pinocchio_log::log;

use crate::error::RdpError;
use crate::state::RingPool;

/// Initialize instruction data layout:
/// - denomination: 8 bytes (u64, lamports)
/// - pool_bump: 1 byte
/// - vault_bump: 1 byte
pub struct InitializeData {
    pub denomination: u64,
    pub pool_bump: u8,
    pub vault_bump: u8,
}

impl InitializeData {
    pub const SIZE: usize = 10;

    pub fn from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::SIZE {
            return Err(RdpError::InvalidInstructionData.into());
        }

        let denomination = u64::from_le_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ]);
        let pool_bump = data[8];
        let vault_bump = data[9];

        Ok(Self { denomination, pool_bump, vault_bump })
    }
}

/// Process initialize instruction
///
/// Accounts:
/// 0. `[writable]` Ring pool account (PDA)
/// 1. `[writable, signer]` Authority (payer)
/// 2. `[]` Vault PDA (for reference, not created here)
/// 3. `[]` System program
pub fn process_initialize(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(RdpError::MissingAccount.into());
    }

    let ring_pool_info = &accounts[0];
    let authority_info = &accounts[1];
    let _system_program = &accounts[2];

    // Verify authority is signer
    if !authority_info.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Parse instruction data
    let init_data = InitializeData::from_bytes(data)?;

    // Verify denomination is valid (minimum 0.01 SOL)
    if init_data.denomination < 10_000_000 {
        return Err(RdpError::InvalidDenomination.into());
    }

    // Verify ring pool is owned by program
    if ring_pool_info.owner() != program_id {
        return Err(RdpError::InvalidAccountOwner.into());
    }

    // Initialize pool
    let mut pool_data = ring_pool_info.try_borrow_mut_data()?;
    
    let mut authority_bytes = [0u8; 32];
    authority_bytes.copy_from_slice(authority_info.key().as_ref());
    
    RingPool::initialize(
        &mut pool_data,
        &authority_bytes,
        init_data.denomination,
        init_data.pool_bump,
        init_data.vault_bump,
    )?;

    log!("Pool initialized");

    Ok(())
}
