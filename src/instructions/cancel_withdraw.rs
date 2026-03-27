//! Cancel Withdraw - Close stuck PendingWithdraw PDA and refund rent to creator

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

use crate::state::pending_withdraw::{PendingWithdraw, PENDING_DISCRIMINATOR};
use crate::error::RdpError;

/// Process cancel_withdraw instruction
/// 
/// Allows the creator to close their PendingWithdraw PDA and reclaim rent.
/// This is useful when a withdraw fails mid-way or user wants to abort.
///
/// Accounts:
/// 0. [writable] PendingWithdraw PDA
/// 1. [writable, signer] Creator (receives rent refund)
pub fn process_cancel_withdraw(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _data: &[u8],
) -> ProgramResult {
    // Parse accounts
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let pending_account = &accounts[0];
    let creator_account = &accounts[1];

    // Verify creator is signer
    if !creator_account.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify pending account is writable
    if !pending_account.is_writable() {
        return Err(RdpError::AccountNotWritable.into());
    }

    // Read pending withdraw data
    let pending_data = pending_account.try_borrow_data()?;
    
    if pending_data.len() < PendingWithdraw::SIZE {
        return Err(RdpError::InvalidAccountDataLen.into());
    }

    // Verify discriminator
    if &pending_data[0..8] != PENDING_DISCRIMINATOR {
        return Err(RdpError::AccountNotInitialized.into());
    }

    // Read creator from PDA and verify it matches signer
    let pending = PendingWithdraw::from_bytes(&pending_data)?;
    if pending.creator != creator_account.key().as_ref() {
        return Err(RdpError::InvalidCreator.into());
    }

    // Drop borrow before modifying lamports
    drop(pending_data);

    // Close account: transfer all lamports to creator
    let pending_lamports = pending_account.lamports();
    
    // Decrease pending account lamports to 0
    unsafe {
        *pending_account.borrow_mut_lamports_unchecked() = 0;
    }
    
    // Increase creator lamports
    unsafe {
        *creator_account.borrow_mut_lamports_unchecked() += pending_lamports;
    }

    // Zero out the account data to mark it as closed
    let mut pending_data_mut = pending_account.try_borrow_mut_data()?;
    pending_data_mut.fill(0);

    Ok(())
}
