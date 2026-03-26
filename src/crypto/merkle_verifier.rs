//! On-Chain Merkle Proof Verifier (Pinocchio Edition)
//!
//! Verifies Merkle proofs for commitment membership
//! Uses SHA-256 for hashing

use crate::error::{RdpError, RdpResult};
use sha2::{Sha256, Digest};

/// Merkle tree depth
pub const MERKLE_DEPTH: usize = 20;

/// Hash size (32 bytes)
pub const HASH_SIZE: usize = 32;

/// Domain separation tags (must match rdp-crypto)
const DOMAIN_MERKLE_LEAF: &[u8] = b"RDP_MERKLE_LEAF_V1";
const DOMAIN_MERKLE_NODE: &[u8] = b"RDP_MERKLE_NODE_V1";

/// Merkle proof data for on-chain verification
#[derive(Clone, Debug)]
pub struct MerkleProofData {
    /// Sibling hashes (20 for depth 20)
    pub siblings: [[u8; HASH_SIZE]; MERKLE_DEPTH],
    /// Leaf index in the tree
    pub leaf_index: u64,
}

impl MerkleProofData {
    /// Serialized size: 20 * 32 + 8 = 648 bytes
    pub const SIZE: usize = (MERKLE_DEPTH * HASH_SIZE) + 8;

    /// Create new empty proof
    pub const fn new() -> Self {
        Self {
            siblings: [[0u8; HASH_SIZE]; MERKLE_DEPTH],
            leaf_index: 0,
        }
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> RdpResult<Self> {
        if data.len() < Self::SIZE {
            return Err(RdpError::MerkleInvalidProofLength.into());
        }

        let mut offset = 0;

        // Read siblings
        let mut siblings = [[0u8; HASH_SIZE]; MERKLE_DEPTH];
        for i in 0..MERKLE_DEPTH {
            siblings[i].copy_from_slice(&data[offset..offset + HASH_SIZE]);
            offset += HASH_SIZE;
        }

        // Read leaf_index (8 bytes, little-endian)
        let leaf_index = u64::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]);

        Ok(Self {
            siblings,
            leaf_index,
        })
    }
}

impl Default for MerkleProofData {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash a leaf (commitment) - must match rdp-crypto
#[inline]
pub fn hash_leaf(commitment: &[u8; 32]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_MERKLE_LEAF);
    hasher.update(commitment);
    let result = hasher.finalize();
    
    let mut output = [0u8; HASH_SIZE];
    output.copy_from_slice(&result);
    output
}

/// Hash two nodes - must match rdp-crypto
#[inline]
pub fn hash_node(left: &[u8; HASH_SIZE], right: &[u8; HASH_SIZE]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_MERKLE_NODE);
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    
    let mut output = [0u8; HASH_SIZE];
    output.copy_from_slice(&result);
    output
}

/// Verify merkle proof on-chain
pub fn verify_merkle_proof(
    commitment: &[u8; 32],
    root: &[u8; HASH_SIZE],
    proof: &MerkleProofData,
) -> RdpResult<()> {
    let mut current = hash_leaf(commitment);
    let mut index = proof.leaf_index;

    for sibling in &proof.siblings {
        if index & 1 == 1 {
            // Current is on the right
            current = hash_node(sibling, &current);
        } else {
            // Current is on the left
            current = hash_node(&current, sibling);
        }
        index >>= 1;
    }

    if current != *root {
        return Err(RdpError::MerkleVerificationFailed.into());
    }

    Ok(())
}

/// Compute root from commitment and proof (without verification)
pub fn compute_root(
    commitment: &[u8; 32],
    proof: &MerkleProofData,
) -> [u8; HASH_SIZE] {
    let mut current = hash_leaf(commitment);
    let mut index = proof.leaf_index;

    for sibling in &proof.siblings {
        if index & 1 == 1 {
            current = hash_node(sibling, &current);
        } else {
            current = hash_node(&current, sibling);
        }
        index >>= 1;
    }

    current
}
