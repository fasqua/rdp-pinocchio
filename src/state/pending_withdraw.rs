//! Pending Withdraw State for 2-TX withdraw flow
//!
//! Used when ring size > 8 (transaction too large for single TX)
//! 
//! Flow:
//! TX1 (PrepareWithdraw): Create PendingWithdraw PDA with ring pubkeys
//! TX2 (ExecuteWithdraw): Verify signature, transfer SOL, close PDA

use crate::error::{RdpError, RdpResult};

/// Maximum ring size
pub const MAX_RING_SIZE: usize = 16;

/// Pending Withdraw discriminator
pub const PENDING_DISCRIMINATOR: &[u8; 8] = b"pending_";

/// Seed for PDA derivation
pub const PENDING_SEED: &[u8] = b"pending";

/// Pending Withdraw Account Layout
///
/// Reordered to avoid alignment padding:
/// - discriminator: 8 bytes (offset 0)
/// - ring_pool: 32 bytes (offset 8)  
/// - amount: 8 bytes (offset 40) - u64 aligned at 8
/// - ring_size: 1 byte (offset 48)
/// - _padding: 7 bytes (offset 49)
/// - ring_pubkeys: 512 bytes (offset 56)
/// - destination: 32 bytes (offset 568)
/// - creator: 32 bytes (offset 600)
/// Total: 632 bytes
#[repr(C)]
pub struct PendingWithdraw {
    /// Discriminator "pending_"
    pub discriminator: [u8; 8],

    /// Associated ring pool
    pub ring_pool: [u8; 32],

    /// Amount to withdraw (moved up for alignment)
    pub amount: u64,

    /// Ring size (2-16)
    pub ring_size: u8,

    /// Explicit padding
    pub _padding: [u8; 7],

    /// Ring pubkeys for signature verification
    pub ring_pubkeys: [[u8; 32]; MAX_RING_SIZE],

    /// Destination address
    pub destination: [u8; 32],

    /// Creator (for refund on close)
    pub creator: [u8; 32],
}

impl PendingWithdraw {
    /// Account size in bytes
    pub const SIZE: usize = 8 + 32 + 8 + 1 + 7 + (MAX_RING_SIZE * 32) + 32 + 32;

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

    /// Initialize pending withdraw
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

        // Check not already initialized
        if &pending.discriminator == PENDING_DISCRIMINATOR {
            return Err(RdpError::AccountAlreadyInitialized.into());
        }

        pending.discriminator = *PENDING_DISCRIMINATOR;
        pending.ring_pool = *ring_pool;
        pending.amount = amount;
        pending.ring_size = ring_size as u8;
        pending._padding = [0u8; 7];
        
        // Copy ring pubkeys
        pending.ring_pubkeys = [[0u8; 32]; MAX_RING_SIZE];
        for i in 0..ring_size {
            pending.ring_pubkeys[i] = ring_pubkeys[i];
        }

        pending.destination = *destination;
        pending.creator = *creator;

        Ok(())
    }

    /// Get ring pubkeys slice
    #[inline(always)]
    pub fn get_ring(&self) -> &[[u8; 32]] {
        &self.ring_pubkeys[..self.ring_size as usize]
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
        assert!(PendingWithdraw::SIZE == 632);
        assert!(core::mem::size_of::<PendingWithdraw>() == 632);
    }

    /// Proof: from_bytes rejects too-small data
    #[kani::proof]
    fn proof_from_bytes_bounds_check() {
        let small_data = [0u8; 100]; // Too small
        let result = PendingWithdraw::from_bytes(&small_data);
        assert!(result.is_err());
    }

    /// Proof: from_bytes_mut_unchecked rejects too-small data
    #[kani::proof]
    fn proof_from_bytes_mut_unchecked_bounds() {
        let mut small_data = [0u8; 100];
        let result = PendingWithdraw::from_bytes_mut_unchecked(&mut small_data);
        assert!(result.is_err());
    }

    /// Proof: get_ring returns correct slice length
    #[kani::proof]
    fn proof_get_ring_len() {
        let mut data = [0u8; 632];
        data[0..8].copy_from_slice(b"pending_");
        
        let pending = unsafe { &mut *(data.as_mut_ptr() as *mut PendingWithdraw) };
        
        pending.ring_size = 8;
        assert!(pending.get_ring().len() == 8);
        
        pending.ring_size = 16;
        assert!(pending.get_ring().len() == 16);
    }
}
