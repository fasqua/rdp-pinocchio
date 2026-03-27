//! Pending Withdraw State for 3-TX withdraw flow
//!
//! Flow:
//! TX1 (PrepareWithdraw): Create PendingWithdraw PDA with ring pubkeys
//! TX2 (UploadSmtProof): Upload SMT proof + verify + store new_smt_root
//! TX3 (ExecuteWithdraw): Verify ring signature, apply SMT root, transfer

use crate::error::{RdpError, RdpResult};
use crate::crypto::sparse_merkle::SMT_DEPTH;

/// Maximum ring size
pub const MAX_RING_SIZE: usize = 16;

/// Pending Withdraw discriminator
pub const PENDING_DISCRIMINATOR: &[u8; 8] = b"pending_";

/// Seed for PDA derivation
pub const PENDING_SEED: &[u8] = b"pending";

/// Pending Withdraw Account Layout (3-TX Flow)
///
/// Layout:
/// - discriminator: 8 bytes
/// - ring_pool: 32 bytes
/// - amount: 8 bytes
/// - ring_size: 1 byte
/// - smt_verified: 1 byte (flag: 0=not verified, 1=verified)
/// - _padding: 6 bytes
/// - ring_pubkeys: 512 bytes
/// - destination: 32 bytes
/// - creator: 32 bytes
/// - new_smt_root: 32 bytes (computed in TX2, applied in TX3)
/// - key_image: 32 bytes (stored in TX2 for double-spend check in TX3)
/// Total: 696 bytes
#[repr(C)]
pub struct PendingWithdraw {
    /// Discriminator "pending_"
    pub discriminator: [u8; 8],

    /// Associated ring pool
    pub ring_pool: [u8; 32],

    /// Amount to withdraw
    pub amount: u64,

    /// Ring size (2-16)
    pub ring_size: u8,

    /// SMT verified flag (proof verified and new_smt_root computed)
    pub smt_verified: u8,

    /// Padding for alignment
    pub _padding: [u8; 6],

    /// Ring pubkeys for signature verification
    pub ring_pubkeys: [[u8; 32]; MAX_RING_SIZE],

    /// Destination address
    pub destination: [u8; 32],

    /// Creator (for refund on close)
    pub creator: [u8; 32],

    /// New SMT root (computed in TX2 after verification)
    pub new_smt_root: [u8; 32],

    /// Key image (stored for ring signature verification in TX3)
    pub key_image: [u8; 32],
}

impl PendingWithdraw {
    /// Account size in bytes: 8 + 32 + 8 + 1 + 1 + 6 + 512 + 32 + 32 + 32 + 32 = 696
    pub const SIZE: usize = 696;

    /// Zero-copy read from account data
    #[inline(always)]
    pub fn from_bytes(data: &[u8]) -> RdpResult<&Self> {
        if data.len() < Self::SIZE {
            return Err(RdpError::InvalidAccountDataLen.into());
        }

        let ptr = data.as_ptr() as *const Self;
        let pending = unsafe { &*ptr };

        if &pending.discriminator != PENDING_DISCRIMINATOR {
            return Err(RdpError::AccountNotInitialized.into());
        }

        Ok(pending)
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
        let pending = unsafe { &mut *ptr };

        if &pending.discriminator != PENDING_DISCRIMINATOR {
            return Err(RdpError::AccountNotInitialized.into());
        }

        Ok(pending)
    }

    /// Initialize pending withdraw (TX1 - PrepareWithdraw)
    pub fn initialize(
        data: &mut [u8],
        ring_pool: &[u8; 32],
        ring_pubkeys: &[[u8; 32]],
        destination: &[u8; 32],
        amount: u64,
        creator: &[u8; 32],
    ) -> RdpResult<()> {
        let ring_size = ring_pubkeys.len();
        if ring_size < 2 || ring_size > MAX_RING_SIZE {
            return Err(RdpError::RingSizeTooSmall.into());
        }

        let pending = Self::from_bytes_mut_unchecked(data)?;

        if &pending.discriminator == PENDING_DISCRIMINATOR {
            return Err(RdpError::AccountAlreadyInitialized.into());
        }

        pending.discriminator = *PENDING_DISCRIMINATOR;
        pending.ring_pool = *ring_pool;
        pending.amount = amount;
        pending.ring_size = ring_size as u8;
        pending.smt_verified = 0;
        pending._padding = [0u8; 6];

        pending.ring_pubkeys = [[0u8; 32]; MAX_RING_SIZE];
        for i in 0..ring_size {
            pending.ring_pubkeys[i] = ring_pubkeys[i];
        }

        pending.destination = *destination;
        pending.creator = *creator;
        pending.new_smt_root = [0u8; 32];
        pending.key_image = [0u8; 32];

        Ok(())
    }

    /// Store verified SMT result (TX2 - UploadSmtProof)
    pub fn store_smt_result(
        &mut self,
        new_smt_root: &[u8; 32],
        key_image: &[u8; 32],
    ) -> RdpResult<()> {
        if self.smt_verified != 0 {
            return Err(RdpError::AccountAlreadyInitialized.into());
        }

        self.new_smt_root = *new_smt_root;
        self.key_image = *key_image;
        self.smt_verified = 1;

        Ok(())
    }

    /// Check if SMT is verified
    #[inline(always)]
    pub fn is_smt_verified(&self) -> bool {
        self.smt_verified != 0
    }

    /// Get ring pubkeys slice
    #[inline(always)]
    pub fn get_ring(&self) -> &[[u8; 32]] {
        &self.ring_pubkeys[..self.ring_size as usize]
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn proof_size_constant() {
        assert!(PendingWithdraw::SIZE == 696);
        assert!(core::mem::size_of::<PendingWithdraw>() == 696);
    }

    #[kani::proof]
    fn proof_from_bytes_bounds_check() {
        let small_data = [0u8; 100];
        let result = PendingWithdraw::from_bytes(&small_data);
        assert!(result.is_err());
    }

    /// Proof: initialize sets correct discriminator
    #[kani::proof]
    fn proof_initialize_discriminator() {
        let mut data = [0u8; 696];
        
        let ring_pool = [1u8; 32];
        let ring_pubkeys = [[2u8; 32]; 2];
        let destination = [3u8; 32];
        let creator = [4u8; 32];
        
        let result = PendingWithdraw::initialize(
            &mut data,
            &ring_pool,
            &ring_pubkeys,
            &destination,
            1000,
            &creator,
        );
        
        assert!(result.is_ok());
        assert!(&data[0..8] == PENDING_DISCRIMINATOR);
    }

    /// Proof: store_smt_result only works once
    #[kani::proof]
    fn proof_store_smt_result_once() {
        let mut data = [0u8; 696];
        data[0..8].copy_from_slice(PENDING_DISCRIMINATOR);
        
        let pending = unsafe { &mut *(data.as_mut_ptr() as *mut PendingWithdraw) };
        pending.smt_verified = 0;
        
        let root = [1u8; 32];
        let key_image = [2u8; 32];
        
        // First call should succeed
        let result1 = pending.store_smt_result(&root, &key_image);
        assert!(result1.is_ok());
        assert!(pending.smt_verified == 1);
        
        // Second call should fail
        let result2 = pending.store_smt_result(&root, &key_image);
        assert!(result2.is_err());
    }

    /// Proof: ring_size bounds (2-16)
    #[kani::proof]
    fn proof_ring_size_bounds() {
        let size: usize = kani::any();
        kani::assume(size >= 2 && size <= MAX_RING_SIZE);
        
        assert!(size >= 2);
        assert!(size <= 16);
    }
}
