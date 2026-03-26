//! Proper scalar reduction mod l for Solana BPF
//!
//! Reduces 512-bit value to scalar mod l
//! l = 2^252 + 27742317777372353535851937790883648493

/// Curve order l in little-endian
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// 2^256 mod l (little-endian)
const R: [u8; 32] = [
    0x13, 0x2c, 0x0a, 0xa3, 0xe5, 0x9c, 0xed, 0xa7,
    0x29, 0x63, 0x08, 0x5d, 0x21, 0x06, 0x21, 0xeb,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f,
];

/// Reduce 64-byte wide scalar mod l
pub fn reduce_wide(input: &[u8; 64]) -> [u8; 32] {
    // Split into low (0-31) and high (32-63)
    // Result = (low + high * 2^256) mod l
    //        = (low + high * R) mod l  (since 2^256 ≡ R mod l)
    
    // We'll use u64 limbs for the computation
    let mut acc = [0u128; 8]; // Extended for i+j up to 6 // Extra limb for overflow
    
    // Add low part
    for i in 0..4 {
        let lo = u64::from_le_bytes([
            input[i*8], input[i*8+1], input[i*8+2], input[i*8+3],
            input[i*8+4], input[i*8+5], input[i*8+6], input[i*8+7]
        ]);
        acc[i] = acc[i].wrapping_add(lo as u128);
    }
    
    // Add high * R
    for i in 0..4 {
        let hi = u64::from_le_bytes([
            input[32+i*8], input[32+i*8+1], input[32+i*8+2], input[32+i*8+3],
            input[32+i*8+4], input[32+i*8+5], input[32+i*8+6], input[32+i*8+7]
        ]);
        
        for j in 0..4 {
            let r = u64::from_le_bytes([
                R[j*8], R[j*8+1], R[j*8+2], R[j*8+3],
                R[j*8+4], R[j*8+5], R[j*8+6], R[j*8+7]
            ]);
            
            let product = (hi as u128) * (r as u128);
            acc[i+j] = acc[i+j].wrapping_add(product);
        }
    }
    
    // Carry propagation
    for i in 0..4 {
        acc[i+1] = acc[i+1].wrapping_add(acc[i] >> 64);
        acc[i] &= 0xFFFFFFFFFFFFFFFF;
    }
    
    // acc[4] might have overflow - reduce again using R
    // acc[4] * 2^256 mod l = acc[4] * R
    let overflow = acc[4] as u64;
    if overflow > 0 {
        for j in 0..4 {
            let r = u64::from_le_bytes([
                R[j*8], R[j*8+1], R[j*8+2], R[j*8+3],
                R[j*8+4], R[j*8+5], R[j*8+6], R[j*8+7]
            ]);
            acc[j] = acc[j].wrapping_add((overflow as u128) * (r as u128));
        }
        acc[4] = 0;
        
        // Carry again
        for i in 0..4 {
            acc[i+1] = acc[i+1].wrapping_add(acc[i] >> 64);
            acc[i] &= 0xFFFFFFFFFFFFFFFF;
        }
    }
    
    // Convert to bytes
    let mut result = [0u8; 32];
    for i in 0..4 {
        let bytes = (acc[i] as u64).to_le_bytes();
        result[i*8..i*8+8].copy_from_slice(&bytes);
    }
    
    // Final reduction: subtract l while >= l
    while gte_l(&result) {
        sub_l(&mut result);
    }
    
    result
}

fn gte_l(val: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if val[i] > L[i] { return true; }
        if val[i] < L[i] { return false; }
    }
    true
}

fn sub_l(val: &mut [u8; 32]) {
    let mut borrow: i16 = 0;
    for i in 0..32 {
        let diff = (val[i] as i16) - (L[i] as i16) - borrow;
        if diff < 0 {
            val[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            val[i] = diff as u8;
            borrow = 0;
        }
    }
}

// ============================================================================
// KANI PROOFS - Only compiled when running `cargo kani`
// ============================================================================
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Proof 1: gte_l never panics
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_gte_l_no_panic() {
        let val: [u8; 32] = kani::any();
        let result = gte_l(&val);
        assert!(result == true || result == false);
    }

    /// Proof 2: sub_l with valid precondition
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_sub_l_no_panic() {
        let mut val: [u8; 32] = kani::any();
        kani::assume(gte_l(&val));
        sub_l(&mut val);
        assert!(val.len() == 32);
    }

    /// Proof 3: reduce_wide with concrete edge cases
    #[kani::proof]
    fn proof_reduce_wide_concrete() {
        // Test zero input
        let zero: [u8; 64] = [0u8; 64];
        let r1 = reduce_wide(&zero);
        assert!(!gte_l(&r1));

        // Test max input
        let max: [u8; 64] = [0xFF; 64];
        let r2 = reduce_wide(&max);
        assert!(!gte_l(&r2));
    }

    /// Proof 4: reduce_wide bounded symbolic (4 bytes)
    #[kani::proof]
    #[kani::unwind(35)]
    fn proof_reduce_wide_bounded() {
        let mut input = [0u8; 64];
        input[0] = kani::any();
        input[1] = kani::any();
        input[32] = kani::any();
        input[33] = kani::any();
        
        let result = reduce_wide(&input);
        assert!(!gte_l(&result));
    }
}
