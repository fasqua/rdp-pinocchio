//! Cryptographic primitives for Ring Diffusion Protocol
//!
//! - CLSAG ring signatures (solana-curve25519 syscalls)
//! - Bulletproofs range proof verification
//! - Merkle tree verification (SHA-256)
//! - Scalar reduction utilities

pub mod ring_verifier;
pub mod merkle_verifier;
pub mod bulletproofs_verifier;
pub mod types;
pub mod scalar_reduce;

pub use ring_verifier::verify_ring_signature;
pub use merkle_verifier::{verify_merkle_proof, compute_root, MerkleProofData, MERKLE_DEPTH, HASH_SIZE};
pub use bulletproofs_verifier::{verify_bulletproof, BulletproofData, RANGE_BITS, IP_ROUNDS};
pub use types::*;
pub use scalar_reduce::reduce_wide;
