//! On-Chain Crypto Types for Pinocchio
//!
//! Zero-copy, no-std compatible types for ring signatures and proofs
//! Replaces Anchor's derive macros with manual implementations

use crate::error::{RdpError, RdpResult};

/// Size constants (must match rdp-crypto)
pub const SCALAR_SIZE: usize = 32;
pub const POINT_SIZE: usize = 32;
pub const KEY_IMAGE_SIZE: usize = 32;

/// Maximum ring size for on-chain verification
pub const MAX_RING_SIZE: usize = 16;

/// Minimum ring size required
pub const MIN_RING_SIZE: usize = 2;

/// Ring signature data for on-chain verification
/// 
/// Layout (for ring size N):
/// - c: 32 bytes (initial challenge)
/// - ring_size: 1 byte
/// - responses: N * 32 bytes
/// - key_image: 32 bytes
#[derive(Clone, Debug)]
pub struct RingSignatureData {
    /// Initial challenge (32 bytes)
    pub c: [u8; SCALAR_SIZE],
    /// Response scalars (one per ring member)
    pub responses: [[u8; SCALAR_SIZE]; MAX_RING_SIZE],
    /// Actual ring size (1-16)
    pub ring_size: u8,
    /// Key image (32 bytes)
    pub key_image: [u8; KEY_IMAGE_SIZE],
}

impl RingSignatureData {
    /// Fixed size for max ring (serialized)
    /// 32 (c) + 1 (ring_size) + 16*32 (responses) + 32 (key_image) = 577 bytes
    pub const MAX_SIZE: usize = SCALAR_SIZE + 1 + (MAX_RING_SIZE * SCALAR_SIZE) + KEY_IMAGE_SIZE;

    /// Create new empty signature data
    pub const fn new() -> Self {
        Self {
            c: [0u8; SCALAR_SIZE],
            responses: [[0u8; SCALAR_SIZE]; MAX_RING_SIZE],
            ring_size: 0,
            key_image: [0u8; KEY_IMAGE_SIZE],
        }
    }

    /// Get actual ring size
    #[inline(always)]
    pub fn ring_size(&self) -> usize {
        self.ring_size as usize
    }

    /// Validate basic structure
    #[inline]
    pub fn validate(&self) -> RdpResult<()> {
        if (self.ring_size as usize) < MIN_RING_SIZE {
            return Err(RdpError::RingSizeTooSmall.into());
        }
        if (self.ring_size as usize) > MAX_RING_SIZE {
            return Err(RdpError::RingSizeTooLarge.into());
        }
        Ok(())
    }

    /// Deserialize from bytes (zero-copy where possible)
    pub fn from_bytes(data: &[u8]) -> RdpResult<Self> {
        // Minimum size: 32 (c) + 1 (ring_size) + 2*32 (min 2 responses) + 32 (key_image)
        const MIN_SIZE: usize = SCALAR_SIZE + 1 + (MIN_RING_SIZE * SCALAR_SIZE) + KEY_IMAGE_SIZE;
        
        if data.len() < MIN_SIZE {
            return Err(RdpError::InvalidInstructionData.into());
        }

        let mut offset = 0;

        // Read c (32 bytes)
        let mut c = [0u8; SCALAR_SIZE];
        c.copy_from_slice(&data[offset..offset + SCALAR_SIZE]);
        offset += SCALAR_SIZE;

        // Read ring_size (1 byte)
        let ring_size = data[offset];
        offset += 1;

        // Validate ring_size before reading responses
        if (ring_size as usize) < MIN_RING_SIZE || (ring_size as usize) > MAX_RING_SIZE {
            return Err(RdpError::RingSizeTooSmall.into());
        }

        // Check we have enough data for responses + key_image
        let expected_len = offset + (ring_size as usize * SCALAR_SIZE) + KEY_IMAGE_SIZE;
        if data.len() < expected_len {
            return Err(RdpError::InvalidInstructionData.into());
        }

        // Read responses
        let mut responses = [[0u8; SCALAR_SIZE]; MAX_RING_SIZE];
        for i in 0..ring_size as usize {
            responses[i].copy_from_slice(&data[offset..offset + SCALAR_SIZE]);
            offset += SCALAR_SIZE;
        }

        // Read key_image (32 bytes)
        let mut key_image = [0u8; KEY_IMAGE_SIZE];
        key_image.copy_from_slice(&data[offset..offset + KEY_IMAGE_SIZE]);

        Ok(Self {
            c,
            responses,
            ring_size,
            key_image,
        })
    }

    /// Get response slice for actual ring size
    #[inline(always)]
    pub fn responses_slice(&self) -> &[[u8; SCALAR_SIZE]] {
        &self.responses[..self.ring_size as usize]
    }
}

impl Default for RingSignatureData {
    fn default() -> Self {
        Self::new()
    }
}
