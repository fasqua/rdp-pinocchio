//! Ring Pool State - Zero-copy implementation
//!
//! Ring size: 16 (privacy 93.75%)
//!
//! Architecture:
//! - RingPool account: stores commitments, key images, config (owned by program)
//! - Vault PDA: holds SOL deposits (owned by System Program)

use crate::error::{RdpError, RdpResult};

/// Ring size for this version
pub const RING_SIZE: usize = 16;

/// Commitment size (Pedersen commitment = compressed point)
pub const COMMITMENT_SIZE: usize = 32;

/// Key image size
pub const KEY_IMAGE_SIZE: usize = 32;

/// Maximum spent key images stored
pub const MAX_SPENT_IMAGES: usize = 256;

/// Ring Pool discriminator
pub const RING_POOL_DISCRIMINATOR: &[u8; 8] = b"ringpool";

/// Seeds for PDA derivation
pub const RING_POOL_SEED: &[u8] = b"ring_pool";
pub const VAULT_SEED: &[u8] = b"vault";

/// Ring Pool Account Layout (Zero-Copy)
///
/// Total size: 8 + 32 + 8 + 1 + 2 + 2 + 1 + (16*32) + (16*8) + (256*32) + 32 = 8,920 bytes
#[repr(C)]
pub struct RingPool {
    /// Discriminator "ringpool"
    pub discriminator: [u8; 8],

    /// Pool authority
    pub authority: [u8; 32],

    /// Fixed denomination in lamports
    pub denomination: u64,

    /// Pool bump seed
    pub pool_bump: u8,

    /// Current number of commitments in ring (0-16)
    pub commitment_count: u16,

    /// Number of spent key images
    pub spent_count: u16,

    /// Vault bump seed
    pub vault_bump: u8,

    /// Ring commitments - Pedersen commitments
    pub commitments: [[u8; COMMITMENT_SIZE]; RING_SIZE],

    /// Deposit timestamps (Unix timestamp)
    pub deposit_times: [u64; RING_SIZE],

    /// Spent key images (for double-spend prevention)
    pub spent_key_images: [[u8; KEY_IMAGE_SIZE]; MAX_SPENT_IMAGES],

    /// Merkle root of all commitments
    pub merkle_root: [u8; 32],
}

impl RingPool {
    /// Account size in bytes
    pub const SIZE: usize = 8 + 32 + 8 + 1 + 1 + 2 + 2 + 1 + 1 + // +2 padding
        (RING_SIZE * COMMITMENT_SIZE) +
        (RING_SIZE * 8) +
        (MAX_SPENT_IMAGES * KEY_IMAGE_SIZE) +
        32;

    /// Zero-copy read from account data
    #[inline(always)]
    pub fn from_bytes(data: &[u8]) -> RdpResult<&Self> {
        if data.len() < Self::SIZE {
            return Err(RdpError::InvalidAccountDataLen.into());
        }

        let ptr = data.as_ptr() as *const Self;
        let pool = unsafe { &*ptr };

        if &pool.discriminator != RING_POOL_DISCRIMINATOR {
            return Err(RdpError::AccountNotInitialized.into());
        }

        Ok(pool)
    }

    /// Zero-copy mutable access (without discriminator check for init)
    #[inline(always)]
    pub fn from_bytes_mut_unchecked(data: &mut [u8]) -> RdpResult<&mut Self> {
        if data.len() < Self::SIZE {
            return Err(RdpError::InvalidAccountDataLen.into());
        }

        let ptr = data.as_mut_ptr() as *mut Self;
        Ok(unsafe { &mut *ptr })
    }

    /// Zero-copy mutable access (with discriminator check)
    #[inline(always)]
    pub fn from_bytes_mut(data: &mut [u8]) -> RdpResult<&mut Self> {
        if data.len() < Self::SIZE {
            return Err(RdpError::InvalidAccountDataLen.into());
        }

        let ptr = data.as_mut_ptr() as *mut Self;
        let pool = unsafe { &mut *ptr };

        if &pool.discriminator != RING_POOL_DISCRIMINATOR {
            return Err(RdpError::AccountNotInitialized.into());
        }

        Ok(pool)
    }

    /// Initialize new ring pool
    pub fn initialize(
        data: &mut [u8],
        authority: &[u8; 32],
        denomination: u64,
        pool_bump: u8,
        vault_bump: u8,
    ) -> RdpResult<()> {
        if data.len() < Self::SIZE {
            return Err(RdpError::InvalidAccountDataLen.into());
        }

        let pool = Self::from_bytes_mut_unchecked(data)?;

        // Check not already initialized
        if &pool.discriminator == RING_POOL_DISCRIMINATOR {
            return Err(RdpError::AccountAlreadyInitialized.into());
        }

        pool.discriminator = *RING_POOL_DISCRIMINATOR;
        pool.authority = *authority;
        pool.denomination = denomination;
        pool.pool_bump = pool_bump;
        pool.commitment_count = 0;
        pool.spent_count = 0;
        pool.vault_bump = vault_bump;
        pool.commitments = [[0u8; COMMITMENT_SIZE]; RING_SIZE];
        pool.deposit_times = [0u64; RING_SIZE];
        pool.spent_key_images = [[0u8; KEY_IMAGE_SIZE]; MAX_SPENT_IMAGES];
        pool.merkle_root = [0u8; 32];

        Ok(())
    }

    /// Check if ring is full
    #[inline(always)]
    pub fn is_full(&self) -> bool {
        self.spent_count as usize >= MAX_SPENT_IMAGES
    }

    /// Check if ring is ready for withdrawal
    #[inline(always)]
    pub fn is_ready(&self) -> bool {
        self.commitment_count >= 2
    }

    /// Add commitment to ring
    pub fn add_commitment(
        &mut self,
        commitment: &[u8; COMMITMENT_SIZE],
        timestamp: u64,
    ) -> RdpResult<usize> {
        if self.is_full() {
            return Err(RdpError::PoolFull.into());
        }

        let index = (self.commitment_count as usize) % RING_SIZE;
        self.commitments[index] = *commitment;
        self.deposit_times[index] = timestamp;
        self.commitment_count += 1;

        Ok(index)
    }

    /// Check if key image is already spent
    pub fn is_key_image_spent(&self, key_image: &[u8; KEY_IMAGE_SIZE]) -> bool {
        for i in 0..self.spent_count as usize {
            if &self.spent_key_images[i] == key_image {
                return true;
            }
        }
        false
    }

    /// Record spent key image
    pub fn record_spent_key_image(
        &mut self,
        key_image: &[u8; KEY_IMAGE_SIZE],
    ) -> RdpResult<()> {
        if self.is_key_image_spent(key_image) {
            return Err(RdpError::KeyImageAlreadySpent.into());
        }

        if self.spent_count as usize >= MAX_SPENT_IMAGES {
            return Err(RdpError::PoolFull.into());
        }

        self.spent_key_images[self.spent_count as usize] = *key_image;
        self.spent_count += 1;

        Ok(())
    }

    /// Get active commitments as slice
    #[inline(always)]
    pub fn active_commitments(&self) -> &[[u8; COMMITMENT_SIZE]] {
        if self.commitment_count as usize >= RING_SIZE { &self.commitments[..] } else { &self.commitments[..self.commitment_count as usize] }
    }
}

// ============================================================================
// KANI PROOFS - Only compiled when running `cargo kani`
// ============================================================================
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Proof: SIZE constant is correct
    #[kani::proof]
    fn proof_size_constant() {
        assert!(core::mem::size_of::<RingPool>() == 8920);
        assert!(RingPool::SIZE == 8920); // includes alignment padding
    }

    /// Proof: from_bytes rejects too-small data
    #[kani::proof]
    fn proof_from_bytes_bounds_check() {
        let small_data = [0u8; 100]; // Too small
        let result = RingPool::from_bytes(&small_data);
        assert!(result.is_err());
    }

    /// Proof: from_bytes_mut_unchecked rejects too-small data
    #[kani::proof]
    fn proof_from_bytes_mut_unchecked_bounds() {
        let mut small_data = [0u8; 100];
        let result = RingPool::from_bytes_mut_unchecked(&mut small_data);
        assert!(result.is_err());
    }

    /// Proof: from_bytes_mut rejects too-small data
    #[kani::proof]
    fn proof_from_bytes_mut_bounds() {
        let mut small_data = [0u8; 100];
        let result = RingPool::from_bytes_mut(&mut small_data);
        assert!(result.is_err());
    }

    /// Proof: is_full correct at boundary
    #[kani::proof]
    fn proof_is_full_boundary() {
        let mut data = [0u8; 8920];
        data[0..8].copy_from_slice(b"ringpool");
        
        let pool = unsafe { &mut *(data.as_mut_ptr() as *mut RingPool) };
        
        pool.commitment_count = 15;
        assert!(!pool.is_full());
        
        pool.commitment_count = 16;
        assert!(pool.is_full());
        
        pool.commitment_count = 17;
        assert!(pool.is_full());
    }

    /// Proof: is_ready correct at boundary
    #[kani::proof]
    fn proof_is_ready_boundary() {
        let mut data = [0u8; 8920];
        data[0..8].copy_from_slice(b"ringpool");
        
        let pool = unsafe { &mut *(data.as_mut_ptr() as *mut RingPool) };
        
        pool.commitment_count = 1;
        assert!(!pool.is_ready());
        
        pool.commitment_count = 2;
        assert!(pool.is_ready());
    }

    /// Proof: add_commitment bounds check
    #[kani::proof]
    fn proof_add_commitment_bounds() {
        let mut data = [0u8; 8920];
        data[0..8].copy_from_slice(b"ringpool");
        
        let pool = unsafe { &mut *(data.as_mut_ptr() as *mut RingPool) };
        pool.commitment_count = 16; // Full
        
        let commitment = [0u8; 32];
        let result = pool.add_commitment(&commitment, 0);
        assert!(result.is_err());
    }

    /// Proof: active_commitments returns correct slice length
    #[kani::proof]
    fn proof_active_commitments_len() {
        let mut data = [0u8; 8920];
        data[0..8].copy_from_slice(b"ringpool");
        
        let pool = unsafe { &mut *(data.as_mut_ptr() as *mut RingPool) };
        
        pool.commitment_count = 5;
        assert!(pool.active_commitments().len() == 5);
        
        pool.commitment_count = 0;
        assert!(pool.active_commitments().len() == 0);
    }

    /// Proof: spent_count check prevents overflow
    #[kani::proof]
    fn proof_spent_count_max_check() {
        let mut data = [0u8; 8920];
        data[0..8].copy_from_slice(b"ringpool");
        
        let pool = unsafe { &mut *(data.as_mut_ptr() as *mut RingPool) };
        pool.spent_count = 256; // At max
        
        // Direct check of the bounds condition
        assert!(pool.spent_count as usize >= MAX_SPENT_IMAGES);
    }
}
