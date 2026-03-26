//! RDP Instructions

pub mod initialize;
pub mod deposit;
pub mod withdraw;
pub mod prepare_withdraw;
pub mod execute_withdraw;

pub use initialize::process_initialize;
pub use deposit::process_deposit;
pub use withdraw::process_withdraw;
pub use prepare_withdraw::process_prepare_withdraw;
pub use execute_withdraw::process_execute_withdraw;

/// Instruction discriminators
#[repr(u8)]
pub enum RdpInstruction {
    /// Initialize ring pool
    Initialize = 0,
    /// Deposit with bulletproof
    Deposit = 1,
    /// Withdraw (single TX, ring size <= 8)
    Withdraw = 2,
    /// Prepare withdraw (TX1 of 2-TX, creates PendingWithdraw PDA)
    PrepareWithdraw = 3,
    /// Execute withdraw (TX2 of 2-TX, verifies and transfers)
    ExecuteWithdraw = 4,
}
