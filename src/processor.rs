//! Instruction processor for RDP

use pinocchio::{account_info::AccountInfo, pubkey::Pubkey, ProgramResult};

use crate::instructions::{
    process_initialize, 
    process_deposit, 
    process_withdraw,
    process_prepare_withdraw,
    process_execute_withdraw,
};

/// Process instruction
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.is_empty() {
        return Err(pinocchio::program_error::ProgramError::InvalidInstructionData);
    }

    let (discriminator, data) = instruction_data.split_at(1);

    match discriminator[0] {
        0 => process_initialize(program_id, accounts, data),
        1 => process_deposit(program_id, accounts, data),
        2 => process_withdraw(program_id, accounts, data),
        3 => process_prepare_withdraw(program_id, accounts, data),
        4 => process_execute_withdraw(program_id, accounts, data),
        _ => Err(pinocchio::program_error::ProgramError::InvalidInstructionData),
    }
}
