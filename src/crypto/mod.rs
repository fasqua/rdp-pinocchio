//! Cryptographic primitives for Ring Diffusion Protocol
//!
//! - CLSAG ring signatures (solana-curve25519 syscalls)
//! - Bulletproofs range proof verification
//! - Merkle tree verification (SHA-256)
//! - Sparse Merkle Tree for key image tracking
//! - Scalar reduction utilities

pub mod ring_verifier;
pub mod merkle_verifier;
pub mod bulletproofs_verifier;
pub mod sparse_merkle;
pub mod types;
pub mod scalar_reduce;

pub use ring_verifier::verify_ring_signature;
pub use merkle_verifier::{verify_merkle_proof, compute_root, MerkleProofData, MERKLE_DEPTH, HASH_SIZE};
pub use bulletproofs_verifier::{verify_bulletproof, BulletproofData, RANGE_BITS, IP_ROUNDS};
pub use sparse_merkle::{SmtProof, verify_and_insert, verify_and_insert_raw, compute_empty_root, SMT_DEPTH, EMPTY_LEAF};
pub use types::*;
pub use scalar_reduce::reduce_wide;
