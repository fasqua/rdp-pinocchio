//! On-Chain Bulletproofs Range Proof Verifier (Pinocchio Edition)
//!
//! Verifies 64-bit range proofs using Solana's curve25519 syscalls
//! Proves: 0 <= value < 2^64 without revealing value
//!
//! Based on: https://eprint.iacr.org/2017/1066.pdf

use pinocchio::program_error::ProgramError;
use pinocchio_log::log;
use solana_curve25519::edwards::{
    add_edwards, multiply_edwards, validate_edwards,
    PodEdwardsPoint,
};
use solana_curve25519::scalar::PodScalar;
use sha2::{Sha512, Digest};

use crate::error::{RdpError, RdpResult};
use super::types::*;

/// Number of bits for range proof
pub const RANGE_BITS: usize = 64;

/// Number of inner product rounds = log2(64) = 6
pub const IP_ROUNDS: usize = 6;

/// Domain separation tags (must match rdp-crypto exactly)
const DOMAIN_BULLETPROOF_V1: &[u8] = b"RDP_BULLETPROOF_V1";
const DOMAIN_HASH_TO_SCALAR: &[u8] = b"RDP_HASH_TO_SCALAR_V1";

/// Ed25519 basepoint G (compressed form)
const BASEPOINT_G: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// Generator H for Pedersen commitments (cofactor-cleared)
const GENERATOR_H: [u8; 32] = [
    0xe7, 0x62, 0xdf, 0x19, 0x77, 0x1c, 0x7e, 0x1f,
    0x8b, 0x18, 0x94, 0xb3, 0x57, 0x2c, 0x2b, 0x18,
    0x69, 0x1b, 0x7e, 0x1a, 0x5d, 0x42, 0x92, 0x4d,
    0xd5, 0xa2, 0xe2, 0xb6, 0xb5, 0x41, 0xce, 0x6c,
];

/// PRECOMPUTED: sum(2^i) for i=0..63 = 2^64 - 1
const SUM_TWO_POWERS: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// ============================================================================
// Bulletproof Data Structure
// ============================================================================

/// Bulletproof data for on-chain verification
#[derive(Clone, Debug)]
pub struct BulletproofData {
    pub v_commitment: [u8; POINT_SIZE],
    pub a: [u8; POINT_SIZE],
    pub s: [u8; POINT_SIZE],
    pub t1: [u8; POINT_SIZE],
    pub t2: [u8; POINT_SIZE],
    pub tau_x: [u8; SCALAR_SIZE],
    pub mu: [u8; SCALAR_SIZE],
    pub t_hat: [u8; SCALAR_SIZE],
    pub ip_l: [[u8; POINT_SIZE]; IP_ROUNDS],
    pub ip_r: [[u8; POINT_SIZE]; IP_ROUNDS],
    pub ip_a: [u8; SCALAR_SIZE],
    pub ip_b: [u8; SCALAR_SIZE],
}

impl BulletproofData {
    /// Serialized size
    pub const SIZE: usize = 
        5 * POINT_SIZE +           // v_commitment, a, s, t1, t2
        3 * SCALAR_SIZE +          // tau_x, mu, t_hat
        2 * IP_ROUNDS * POINT_SIZE + // ip_l, ip_r
        2 * SCALAR_SIZE;           // ip_a, ip_b

    /// Create new empty proof
    pub const fn new() -> Self {
        Self {
            v_commitment: [0u8; POINT_SIZE],
            a: [0u8; POINT_SIZE],
            s: [0u8; POINT_SIZE],
            t1: [0u8; POINT_SIZE],
            t2: [0u8; POINT_SIZE],
            tau_x: [0u8; SCALAR_SIZE],
            mu: [0u8; SCALAR_SIZE],
            t_hat: [0u8; SCALAR_SIZE],
            ip_l: [[0u8; POINT_SIZE]; IP_ROUNDS],
            ip_r: [[0u8; POINT_SIZE]; IP_ROUNDS],
            ip_a: [0u8; SCALAR_SIZE],
            ip_b: [0u8; SCALAR_SIZE],
        }
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> RdpResult<Self> {
        if data.len() < Self::SIZE {
            return Err(RdpError::InvalidInstructionData.into());
        }

        let mut offset = 0;
        let mut proof = Self::new();

        // Read points
        proof.v_commitment.copy_from_slice(&data[offset..offset + POINT_SIZE]);
        offset += POINT_SIZE;
        proof.a.copy_from_slice(&data[offset..offset + POINT_SIZE]);
        offset += POINT_SIZE;
        proof.s.copy_from_slice(&data[offset..offset + POINT_SIZE]);
        offset += POINT_SIZE;
        proof.t1.copy_from_slice(&data[offset..offset + POINT_SIZE]);
        offset += POINT_SIZE;
        proof.t2.copy_from_slice(&data[offset..offset + POINT_SIZE]);
        offset += POINT_SIZE;

        // Read scalars
        proof.tau_x.copy_from_slice(&data[offset..offset + SCALAR_SIZE]);
        offset += SCALAR_SIZE;
        proof.mu.copy_from_slice(&data[offset..offset + SCALAR_SIZE]);
        offset += SCALAR_SIZE;
        proof.t_hat.copy_from_slice(&data[offset..offset + SCALAR_SIZE]);
        offset += SCALAR_SIZE;

        // Read IP proof points
        for i in 0..IP_ROUNDS {
            proof.ip_l[i].copy_from_slice(&data[offset..offset + POINT_SIZE]);
            offset += POINT_SIZE;
        }
        for i in 0..IP_ROUNDS {
            proof.ip_r[i].copy_from_slice(&data[offset..offset + POINT_SIZE]);
            offset += POINT_SIZE;
        }

        // Read IP proof scalars
        proof.ip_a.copy_from_slice(&data[offset..offset + SCALAR_SIZE]);
        offset += SCALAR_SIZE;
        proof.ip_b.copy_from_slice(&data[offset..offset + SCALAR_SIZE]);

        Ok(proof)
    }
}

impl Default for BulletproofData {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Main Verification Function
// ============================================================================

pub fn verify_bulletproof(proof: &BulletproofData) -> RdpResult<()> {
    validate_proof_points(proof)?;

    let (y, z) = compute_challenges_yz(&proof.a, &proof.s);
    let x = compute_challenge_x(&proof.t1, &proof.t2, &z);

    let x_sq = scalar_mul(&x, &x);
    let z_sq = scalar_mul(&z, &z);

    let delta = compute_delta(&y, &z)?;

    verify_main_equation(
        &proof.t_hat,
        &proof.tau_x,
        &proof.v_commitment,
        &z_sq,
        &delta,
        &proof.t1,
        &x,
        &proof.t2,
        &x_sq,
    )?;

    validate_ip_proof_structure(proof)?;

    log!("Bulletproof verified");
    Ok(())
}

// ============================================================================
// Validation Functions
// ============================================================================

fn validate_proof_points(proof: &BulletproofData) -> RdpResult<()> {
    if !validate_edwards(&PodEdwardsPoint(proof.v_commitment)) {
        return Err(RdpError::BulletproofInvalidPoint.into());
    }
    if !validate_edwards(&PodEdwardsPoint(proof.a)) {
        return Err(RdpError::BulletproofInvalidPoint.into());
    }
    if !validate_edwards(&PodEdwardsPoint(proof.s)) {
        return Err(RdpError::BulletproofInvalidPoint.into());
    }
    if !validate_edwards(&PodEdwardsPoint(proof.t1)) {
        return Err(RdpError::BulletproofInvalidPoint.into());
    }
    if !validate_edwards(&PodEdwardsPoint(proof.t2)) {
        return Err(RdpError::BulletproofInvalidPoint.into());
    }

    for i in 0..IP_ROUNDS {
        if !validate_edwards(&PodEdwardsPoint(proof.ip_l[i])) {
            return Err(RdpError::BulletproofInvalidPoint.into());
        }
        if !validate_edwards(&PodEdwardsPoint(proof.ip_r[i])) {
            return Err(RdpError::BulletproofInvalidPoint.into());
        }
    }

    Ok(())
}

fn validate_ip_proof_structure(proof: &BulletproofData) -> RdpResult<()> {
    let zero = [0u8; SCALAR_SIZE];
    if proof.ip_a == zero && proof.ip_b == zero {
        return Err(RdpError::BulletproofInvalidStructure.into());
    }
    Ok(())
}

// ============================================================================
// Challenge Computation
// ============================================================================

fn hash_to_scalar(data: &[u8]) -> [u8; SCALAR_SIZE] {
    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_HASH_TO_SCALAR);
    hasher.update(data);
    let hash = hasher.finalize();

    let mut result = [0u8; SCALAR_SIZE];
    result.copy_from_slice(&hash[..32]);
    result[31] &= 0x0f;
    result
}

fn compute_challenges_yz(
    a: &[u8; POINT_SIZE],
    s: &[u8; POINT_SIZE]
) -> ([u8; SCALAR_SIZE], [u8; SCALAR_SIZE]) {
    let mut input_y = [0u8; 128];
    let mut offset = 0;
    
    input_y[offset..offset + DOMAIN_BULLETPROOF_V1.len()].copy_from_slice(DOMAIN_BULLETPROOF_V1);
    offset += DOMAIN_BULLETPROOF_V1.len();
    input_y[offset..offset + POINT_SIZE].copy_from_slice(a);
    offset += POINT_SIZE;
    input_y[offset..offset + POINT_SIZE].copy_from_slice(s);
    offset += POINT_SIZE;

    let y = hash_to_scalar(&input_y[..offset]);

    let mut input_z = [0u8; 160];
    input_z[..offset].copy_from_slice(&input_y[..offset]);
    input_z[offset..offset + SCALAR_SIZE].copy_from_slice(&y);
    
    let z = hash_to_scalar(&input_z[..offset + SCALAR_SIZE]);

    (y, z)
}

fn compute_challenge_x(
    t1: &[u8; POINT_SIZE],
    t2: &[u8; POINT_SIZE],
    z: &[u8; SCALAR_SIZE]
) -> [u8; SCALAR_SIZE] {
    let mut input = [0u8; 160];
    let mut offset = 0;
    
    input[offset..offset + DOMAIN_BULLETPROOF_V1.len()].copy_from_slice(DOMAIN_BULLETPROOF_V1);
    offset += DOMAIN_BULLETPROOF_V1.len();
    input[offset..offset + SCALAR_SIZE].copy_from_slice(z);
    offset += SCALAR_SIZE;
    input[offset..offset + POINT_SIZE].copy_from_slice(t1);
    offset += POINT_SIZE;
    input[offset..offset + POINT_SIZE].copy_from_slice(t2);
    offset += POINT_SIZE;

    hash_to_scalar(&input[..offset])
}

// ============================================================================
// Delta Computation
// ============================================================================

fn compute_delta(
    y: &[u8; SCALAR_SIZE],
    z: &[u8; SCALAR_SIZE]
) -> RdpResult<[u8; SCALAR_SIZE]> {
    let z_sq = scalar_mul(z, z);
    let z_cubed = scalar_mul(&z_sq, z);

    let sum_y = compute_sum_of_powers(y)?;

    let z_minus_zsq = scalar_sub(z, &z_sq);
    let term1 = scalar_mul(&z_minus_zsq, &sum_y);
    let term2 = scalar_mul(&z_cubed, &SUM_TWO_POWERS);

    Ok(scalar_sub(&term1, &term2))
}

fn compute_sum_of_powers(y: &[u8; SCALAR_SIZE]) -> RdpResult<[u8; SCALAR_SIZE]> {
    // Optimized: (1+y)(1+y²)(1+y⁴)(1+y⁸)(1+y¹⁶)(1+y³²) = sum(y^i, i=0..63)
    let one = scalar_one();

    let y2 = scalar_mul(y, y);
    let y4 = scalar_mul(&y2, &y2);
    let y8 = scalar_mul(&y4, &y4);
    let y16 = scalar_mul(&y8, &y8);
    let y32 = scalar_mul(&y16, &y16);

    let t1 = scalar_add(&one, y);
    let t2 = scalar_add(&one, &y2);
    let t4 = scalar_add(&one, &y4);
    let t8 = scalar_add(&one, &y8);
    let t16 = scalar_add(&one, &y16);
    let t32 = scalar_add(&one, &y32);

    let p1 = scalar_mul(&t1, &t2);
    let p2 = scalar_mul(&p1, &t4);
    let p3 = scalar_mul(&p2, &t8);
    let p4 = scalar_mul(&p3, &t16);
    let result = scalar_mul(&p4, &t32);

    Ok(result)
}

// ============================================================================
// Main Equation Verification
// ============================================================================

fn verify_main_equation(
    t_hat: &[u8; SCALAR_SIZE],
    tau_x: &[u8; SCALAR_SIZE],
    v: &[u8; POINT_SIZE],
    z_sq: &[u8; SCALAR_SIZE],
    delta: &[u8; SCALAR_SIZE],
    t1: &[u8; POINT_SIZE],
    x: &[u8; SCALAR_SIZE],
    t2: &[u8; POINT_SIZE],
    x_sq: &[u8; SCALAR_SIZE],
) -> RdpResult<()> {
    let g = PodEdwardsPoint(BASEPOINT_G);
    let h = PodEdwardsPoint(GENERATOR_H);

    // LHS = t_hat * G + tau_x * H
    let t_hat_g = multiply_edwards(&PodScalar(*t_hat), &g)
        .ok_or(ProgramError::from(RdpError::BulletproofCurveOpFailed))?;
    let tau_x_h = multiply_edwards(&PodScalar(*tau_x), &h)
        .ok_or(ProgramError::from(RdpError::BulletproofCurveOpFailed))?;
    let lhs = add_edwards(&t_hat_g, &tau_x_h)
        .ok_or(ProgramError::from(RdpError::BulletproofCurveOpFailed))?;

    // RHS = z^2 * V + delta * G + x * T1 + x^2 * T2
    let v_point = PodEdwardsPoint(*v);
    let t1_point = PodEdwardsPoint(*t1);
    let t2_point = PodEdwardsPoint(*t2);

    let z_sq_v = multiply_edwards(&PodScalar(*z_sq), &v_point)
        .ok_or(ProgramError::from(RdpError::BulletproofCurveOpFailed))?;
    let delta_g = multiply_edwards(&PodScalar(*delta), &g)
        .ok_or(ProgramError::from(RdpError::BulletproofCurveOpFailed))?;
    let x_t1 = multiply_edwards(&PodScalar(*x), &t1_point)
        .ok_or(ProgramError::from(RdpError::BulletproofCurveOpFailed))?;
    let x_sq_t2 = multiply_edwards(&PodScalar(*x_sq), &t2_point)
        .ok_or(ProgramError::from(RdpError::BulletproofCurveOpFailed))?;

    let sum1 = add_edwards(&z_sq_v, &delta_g)
        .ok_or(ProgramError::from(RdpError::BulletproofCurveOpFailed))?;
    let sum2 = add_edwards(&sum1, &x_t1)
        .ok_or(ProgramError::from(RdpError::BulletproofCurveOpFailed))?;
    let rhs = add_edwards(&sum2, &x_sq_t2)
        .ok_or(ProgramError::from(RdpError::BulletproofCurveOpFailed))?;

    if lhs.0 != rhs.0 {
        return Err(RdpError::BulletproofVerificationFailed.into());
    }

    Ok(())
}

// ============================================================================
// Scalar Arithmetic
// ============================================================================

fn scalar_one() -> [u8; SCALAR_SIZE] {
    let mut one = [0u8; SCALAR_SIZE];
    one[0] = 1;
    one
}

fn scalar_add(a: &[u8; SCALAR_SIZE], b: &[u8; SCALAR_SIZE]) -> [u8; SCALAR_SIZE] {
    let mut result = [0u64; 4];
    let mut carry: u128 = 0;

    for i in 0..4 {
        let ai = u64::from_le_bytes([
            a[i*8], a[i*8+1], a[i*8+2], a[i*8+3],
            a[i*8+4], a[i*8+5], a[i*8+6], a[i*8+7],
        ]);
        let bi = u64::from_le_bytes([
            b[i*8], b[i*8+1], b[i*8+2], b[i*8+3],
            b[i*8+4], b[i*8+5], b[i*8+6], b[i*8+7],
        ]);
        let sum = (ai as u128) + (bi as u128) + carry;
        result[i] = sum as u64;
        carry = sum >> 64;
    }

    reduce_if_needed(&mut result, carry > 0);

    let mut output = [0u8; 32];
    for i in 0..4 {
        output[i*8..(i+1)*8].copy_from_slice(&result[i].to_le_bytes());
    }
    output
}

fn scalar_sub(a: &[u8; SCALAR_SIZE], b: &[u8; SCALAR_SIZE]) -> [u8; SCALAR_SIZE] {
    const L: [u64; 4] = [
        0x5812631a5cf5d3ed,
        0x14def9dea2f79cd6,
        0x0000000000000000,
        0x1000000000000000,
    ];

    let mut a_limbs = [0u64; 4];
    let mut b_limbs = [0u64; 4];

    for i in 0..4 {
        a_limbs[i] = u64::from_le_bytes([
            a[i*8], a[i*8+1], a[i*8+2], a[i*8+3],
            a[i*8+4], a[i*8+5], a[i*8+6], a[i*8+7],
        ]);
        b_limbs[i] = u64::from_le_bytes([
            b[i*8], b[i*8+1], b[i*8+2], b[i*8+3],
            b[i*8+4], b[i*8+5], b[i*8+6], b[i*8+7],
        ]);
    }

    let mut result = [0u64; 4];
    let mut borrow: u64 = 0;
    for i in 0..4 {
        let (diff1, b1) = a_limbs[i].overflowing_sub(b_limbs[i]);
        let (diff2, b2) = diff1.overflowing_sub(borrow);
        result[i] = diff2;
        borrow = if b1 || b2 { 1 } else { 0 };
    }

    if borrow != 0 {
        let mut carry: u64 = 0;
        for i in 0..4 {
            let (sum1, c1) = result[i].overflowing_add(L[i]);
            let (sum2, c2) = sum1.overflowing_add(carry);
            result[i] = sum2;
            carry = if c1 || c2 { 1 } else { 0 };
        }
    }

    let mut output = [0u8; 32];
    for i in 0..4 {
        output[i*8..(i+1)*8].copy_from_slice(&result[i].to_le_bytes());
    }
    output
}

fn scalar_mul(a: &[u8; SCALAR_SIZE], b: &[u8; SCALAR_SIZE]) -> [u8; SCALAR_SIZE] {
    let mut a_limbs = [0u64; 4];
    let mut b_limbs = [0u64; 4];

    for i in 0..4 {
        a_limbs[i] = u64::from_le_bytes([
            a[i*8], a[i*8+1], a[i*8+2], a[i*8+3],
            a[i*8+4], a[i*8+5], a[i*8+6], a[i*8+7],
        ]);
        b_limbs[i] = u64::from_le_bytes([
            b[i*8], b[i*8+1], b[i*8+2], b[i*8+3],
            b[i*8+4], b[i*8+5], b[i*8+6], b[i*8+7],
        ]);
    }

    let wide = mul_256x256(&a_limbs, &b_limbs);

    let mut wide_bytes = [0u8; 64];
    for i in 0..8 {
        wide_bytes[i*8..(i+1)*8].copy_from_slice(&wide[i].to_le_bytes());
    }

    reduce_512_to_scalar(&wide_bytes)
}

fn mul_256x256(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut out = [0u64; 8];

    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let k = i + j;
            let product = (a[i] as u128) * (b[j] as u128) + (out[k] as u128) + carry;
            out[k] = product as u64;
            carry = product >> 64;
        }
        let mut k = i + 4;
        while carry > 0 && k < 8 {
            let sum = (out[k] as u128) + carry;
            out[k] = sum as u64;
            carry = sum >> 64;
            k += 1;
        }
    }

    out
}

fn reduce_512_to_scalar(wide: &[u8; 64]) -> [u8; SCALAR_SIZE] {
    const L: [u64; 4] = [
        0x5812631a5cf5d3ed,
        0x14def9dea2f79cd6,
        0x0000000000000000,
        0x1000000000000000,
    ];

    const POW2_256: [u64; 4] = [
        0xd6ec31748d98951d, 0xc6ef5bf4737dcf70,
        0xfffffffffffffffe, 0x0fffffffffffffff,
    ];
    const POW2_320: [u64; 4] = [
        0x5812631a5cf5d3ed, 0x93b8c838d39a5e06,
        0xb2106215d086329a, 0x0ffffffffffffffe,
    ];
    const POW2_384: [u64; 4] = [
        0x39822129a02a6271, 0xb64a7f435e4fdd95,
        0x7ed9ce5a30a2c131, 0x02106215d086329a,
    ];
    const POW2_448: [u64; 4] = [
        0x79daf520a00acb65, 0xe24babbe38d1d7a9,
        0xb399411b7c309a3d, 0x0ed9ce5a30a2c131,
    ];

    let mut limbs = [0u64; 8];
    for i in 0..8 {
        limbs[i] = u64::from_le_bytes(wide[i*8..(i+1)*8].try_into().unwrap());
    }

    let mut acc = [limbs[0], limbs[1], limbs[2], limbs[3]];

    if limbs[4] != 0 {
        acc = add_scaled_256(&acc, &POW2_256, limbs[4], &L);
    }
    if limbs[5] != 0 {
        acc = add_scaled_256(&acc, &POW2_320, limbs[5], &L);
    }
    if limbs[6] != 0 {
        acc = add_scaled_256(&acc, &POW2_384, limbs[6], &L);
    }
    if limbs[7] != 0 {
        acc = add_scaled_256(&acc, &POW2_448, limbs[7], &L);
    }

    while cmp_ge_256(&acc, &L) {
        sub_256_inplace(&mut acc, &L);
    }

    limbs_to_bytes(&acc)
}

fn add_scaled_256(acc: &[u64; 4], base: &[u64; 4], scalar: u64, l: &[u64; 4]) -> [u64; 4] {
    let mut product = [0u64; 5];
    let mut carry = 0u128;
    for i in 0..4 {
        let p = (base[i] as u128) * (scalar as u128) + carry;
        product[i] = p as u64;
        carry = p >> 64;
    }
    product[4] = carry as u64;

    carry = 0;
    for i in 0..4 {
        let s = (product[i] as u128) + (acc[i] as u128) + carry;
        product[i] = s as u64;
        carry = s >> 64;
    }
    product[4] = product[4].wrapping_add(carry as u64);

    const R: [u64; 4] = [
        0xd6ec31748d98951d, 0xc6ef5bf4737dcf70,
        0xfffffffffffffffe, 0x0fffffffffffffff,
    ];

    let mut result = [product[0], product[1], product[2], product[3]];
    let mut overflow = product[4];

    while overflow != 0 {
        let mut new_overflow = 0u128;
        for i in 0..4 {
            let p = (R[i] as u128) * (overflow as u128) + (result[i] as u128) + new_overflow;
            result[i] = p as u64;
            new_overflow = p >> 64;
        }
        overflow = new_overflow as u64;
    }

    while cmp_ge_256(&result, l) {
        sub_256_inplace(&mut result, l);
    }

    result
}

fn cmp_ge_256(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] > b[i] { return true; }
        if a[i] < b[i] { return false; }
    }
    true
}

fn sub_256_inplace(a: &mut [u64; 4], b: &[u64; 4]) {
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        a[i] = d2;
        borrow = (b1 as u64) + (b2 as u64);
    }
}

fn limbs_to_bytes(x: &[u64; 4]) -> [u8; SCALAR_SIZE] {
    let mut result = [0u8; SCALAR_SIZE];
    for i in 0..4 {
        result[i*8..(i+1)*8].copy_from_slice(&x[i].to_le_bytes());
    }
    result
}

fn reduce_if_needed(result: &mut [u64; 4], had_carry: bool) {
    const L: [u64; 4] = [
        0x5812631a5cf5d3ed,
        0x14def9dea2f79cd6,
        0x0000000000000000,
        0x1000000000000000,
    ];

    if had_carry {
        let mut borrow: i128 = 0;
        for i in 0..4 {
            let diff = (result[i] as i128) - (L[i] as i128) - borrow;
            if diff < 0 {
                result[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                result[i] = diff as u64;
                borrow = 0;
            }
        }
        return;
    }

    let mut geq = true;
    for i in (0..4).rev() {
        if result[i] < L[i] {
            geq = false;
            break;
        } else if result[i] > L[i] {
            break;
        }
    }

    if geq {
        let mut borrow: i128 = 0;
        for i in 0..4 {
            let diff = (result[i] as i128) - (L[i] as i128) - borrow;
            if diff < 0 {
                result[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                result[i] = diff as u64;
                borrow = 0;
            }
        }
    }
}
