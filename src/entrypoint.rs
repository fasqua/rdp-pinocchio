//! Program entrypoint for Ring Diffusion Protocol
//!
//! Pinocchio-based entrypoint - zero dependencies, minimal overhead

use pinocchio::{
    account_info::AccountInfo,
    entrypoint,
    pubkey::Pubkey,
    ProgramResult,
};

use crate::processor::process_instruction;

entrypoint!(process_instruction_entrypoint);

/// Program entrypoint
fn process_instruction_entrypoint(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    process_instruction(program_id, accounts, instruction_data)
}
