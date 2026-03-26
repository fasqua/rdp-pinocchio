//! Ring Diffusion Protocol - Pinocchio Edition
//!
//! Privacy-preserving transfers on Solana using:
//! - Ring signatures (CLSAG) for sender anonymity
//! - Pedersen commitments for amount hiding
//! - Bulletproofs for range proof verification

#![cfg_attr(not(test), no_std)]

pub mod error;
pub mod crypto;
pub mod state;
pub mod instructions;
pub mod processor;

#[cfg(not(feature = "no-entrypoint"))]
pub mod entrypoint;

// Re-exports
pub use error::{RdpError, RdpResult};
pub use state::{RingPool, PendingWithdraw, RING_SIZE, COMMITMENT_SIZE, KEY_IMAGE_SIZE};
pub use crypto::{RingSignatureData, BulletproofData, verify_ring_signature, verify_bulletproof};
pub use instructions::RdpInstruction;
