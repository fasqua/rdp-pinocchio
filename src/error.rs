//! Custom error types for RDP Pinocchio
//!
//! Replaces Anchor's #[error_code] macro with manual ProgramError implementation

use pinocchio::program_error::ProgramError;

/// RDP Error codes
/// Using offset 6000 to avoid collision with built-in errors
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RdpError {
    // === Ring Signature Errors (6000-6009) ===
    /// Ring size too small (minimum 2)
    RingSizeTooSmall = 6000,
    /// Ring size too large (maximum 16)
    RingSizeTooLarge = 6001,
    /// Ring size mismatch with signature
    RingSizeMismatch = 6002,
    /// Invalid point on curve
    InvalidPoint = 6003,
    /// Invalid key image
    InvalidKeyImage = 6004,
    /// Ring signature verification failed
    RingVerificationFailed = 6005,
    /// Curve operation failed
    CurveOperationFailed = 6006,

    // === Bulletproof Errors (6010-6019) ===
    /// Invalid bulletproof point
    BulletproofInvalidPoint = 6010,
    /// Bulletproof curve operation failed
    BulletproofCurveOpFailed = 6011,
    /// Range proof verification failed
    BulletproofVerificationFailed = 6012,
    /// Invalid proof structure
    BulletproofInvalidStructure = 6013,

    // === Merkle Errors (6020-6029) ===
    /// Invalid proof length (must be 20 siblings)
    MerkleInvalidProofLength = 6020,
    /// Merkle proof verification failed
    MerkleVerificationFailed = 6021,

    // === Pool Errors (6030-6039) ===
    /// Ring pool is full
    PoolFull = 6030,
    /// Ring pool not ready (need more commitments)
    PoolNotReady = 6031,
    /// Key image already spent (double-spend attempt)
    KeyImageAlreadySpent = 6032,
    /// Invalid denomination
    InvalidDenomination = 6033,

    // === Account Errors (6040-6049) ===
    /// Account not initialized
    AccountNotInitialized = 6040,
    /// Account already initialized
    AccountAlreadyInitialized = 6041,
    /// Invalid account owner
    InvalidAccountOwner = 6042,
    /// Invalid PDA derivation
    InvalidPDA = 6043,
    /// Invalid account data length
    InvalidAccountDataLen = 6044,

    // === Instruction Errors (6050-6059) ===
    /// Invalid instruction data
    InvalidInstructionData = 6050,
    /// Missing required account
    MissingAccount = 6051,
    /// Arithmetic overflow
    ArithmeticOverflow = 6052,
}

impl From<RdpError> for ProgramError {
    fn from(e: RdpError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

/// Result type alias for RDP operations
pub type RdpResult<T> = Result<T, ProgramError>;
