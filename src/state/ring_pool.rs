//! Ring Pool State - Zero-copy implementation
//!
//! Ring size: 16 (privacy 93.75%)
//!
//! Architecture:
//! - RingPool account: stores commitments, SMT root, config (owned by program)
//! - Vault PDA: holds SOL deposits (owned by System Program)

use crate::error::{RdpError, RdpResult};
use crate::crypto::sparse_merkle::compute_empty_root;

/// Ring size for this version
pub const RING_SIZE: usize = 16;

/// Commitment size (Pedersen commitment = compressed point)
pub const COMMITMENT_SIZE: usize = 32;

/// Key image size
pub const KEY_IMAGE_SIZE: usize = 32;


/// Ring Pool discriminator
pub const RING_POOL_DISCRIMINATOR: &[u8; 8] = b"ringpool";

/// Seeds for PDA derivation
pub const RING_POOL_SEED: &[u8] = b"ring_pool";
pub const VAULT_SEED: &[u8] = b"vault";

/// Ring Pool Account Layout (Zero-Copy)
///
/// Total size: 8 + 32 + 8 + 1 + 2 + 8 + 1 + (16*32) + (16*8) + 32 + 32 = 728 bytes
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

    /// Number of spent key images (unlimited with SMT)
    pub spent_count: u64,

    /// Vault bump seed
    pub vault_bump: u8,

    /// Ring commitments - Pedersen commitments
    pub commitments: [[u8; COMMITMENT_SIZE]; RING_SIZE],

    /// Deposit timestamps (Unix timestamp)
    pub deposit_times: [u64; RING_SIZE],

    /// Sparse Merkle Tree root for spent key images (unlimited withdrawals)
    pub smt_root: [u8; 32],

    /// Merkle root of all commitments
    pub merkle_root: [u8; 32],
}

impl RingPool {
    /// Account size in bytes
    /// Layout: discriminator(8) + authority(32) + denomination(8) + pool_bump(1) + 
    /// commitment_count(2) + spent_count(8) + vault_bump(1) + padding(4) +
    /// commitments(16*32=512) + deposit_times(16*8=128) + smt_root(32) + merkle_root(32) = 768 bytes
    pub const SIZE: usize = 776;

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
        pool.smt_root = compute_empty_root(); // Initialize empty SMT
        pool.merkle_root = [0u8; 32];

        Ok(())
    }

    /// Check if pool is full (SMT is never full - unlimited withdrawals)
    #[inline(always)]
    pub fn is_full(&self) -> bool {
        self.commitment_count >= RING_SIZE as u16
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

    /// Get SMT root for external verification
    #[inline(always)]
    pub fn get_smt_root(&self) -> &[u8; 32] {
        &self.smt_root
    }

    /// Update SMT root after successful withdrawal verification
    /// The verification is done externally using verify_and_insert
    pub fn update_smt_root(&mut self, new_root: &[u8; 32]) {
        self.smt_root = *new_root;
        self.spent_count += 1;
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
        assert!(core::mem::size_of::<RingPool>() == 776);
        assert!(RingPool::SIZE == 776);
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


    /// Proof: is_ready correct at boundary
    #[kani::proof]
    fn proof_is_ready_boundary() {
        let mut data = [0u8; 776];
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
        let mut data = [0u8; 776];
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
        let mut data = [0u8; 776];
        data[0..8].copy_from_slice(b"ringpool");
        
        let pool = unsafe { &mut *(data.as_mut_ptr() as *mut RingPool) };
        
        pool.commitment_count = 5;
        assert!(pool.active_commitments().len() == 5);
        
        pool.commitment_count = 0;
        assert!(pool.active_commitments().len() == 0);
    }

    /// Proof: update_smt_root increments spent_count
    #[kani::proof]
    fn proof_update_smt_root() {
        let mut data = [0u8; 776];
        data[0..8].copy_from_slice(b"ringpool");

        let pool = unsafe { &mut *(data.as_mut_ptr() as *mut RingPool) };
        pool.spent_count = 0;

        let new_root = [1u8; 32];
        pool.update_smt_root(&new_root);

        assert!(pool.spent_count == 1);
        assert!(pool.smt_root == new_root);
    }

    /// Proof: slot index is always within bounds  
    #[kani::proof]
    fn proof_slot_index_bounded() {
        let count: u16 = kani::any();
        kani::assume(count < 1000);
        
        let index = (count as usize) % RING_SIZE;
        assert!(index < RING_SIZE);
    }

    /// Proof: is_full returns true when commitment_count >= RING_SIZE
    #[kani::proof]
    fn proof_is_full_at_capacity() {
        let mut data = [0u8; 776];
        data[0..8].copy_from_slice(b"ringpool");

        let pool = unsafe { &mut *(data.as_mut_ptr() as *mut RingPool) };
        
        pool.commitment_count = 16;
        assert!(pool.is_full());
        
        pool.commitment_count = 17;
        assert!(pool.is_full());
        
        pool.commitment_count = 15;
        assert!(!pool.is_full());
    }
}
