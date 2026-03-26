//! On-Chain Ring Signature Verifier (Pinocchio Edition)
//!
//! Verifies CLSAG ring signatures using Solana's native curve25519 syscalls
//! Optimized for minimal CU usage

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

/// Ed25519 basepoint (generator G) in compressed form
const BASEPOINT: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// Identity point
const IDENTITY: [u8; 32] = [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Domain separation for ring challenge
const DOMAIN_RING_CHALLENGE: &[u8] = b"RDP_RING_CHALLENGE_V1";
const DOMAIN_KEY_IMAGE: &[u8] = b"RDP_KEY_IMAGE_V1";
const DOMAIN_HASH_TO_POINT: &[u8] = b"RDP_HASH_TO_POINT_V1";

/// Verify a ring signature on-chain
pub fn verify_ring_signature(
    message: &[u8],
    ring: &[[u8; POINT_SIZE]],
    signature: &RingSignatureData,
) -> RdpResult<()> {
    // Validate inputs
    signature.validate()?;
    
    if ring.len() != signature.ring_size() {
        return Err(RdpError::RingSizeMismatch.into());
    }

    // Validate key image is on curve and not identity
    let key_image = PodEdwardsPoint(signature.key_image);
    if !validate_edwards(&key_image) {
        return Err(RdpError::InvalidKeyImage.into());
    }
    if signature.key_image == IDENTITY {
        return Err(RdpError::InvalidKeyImage.into());
    }

    // Start with c_0
    let mut c = signature.c;

    // Verify around the ring
    for i in 0..ring.len() {
        // Validate ring member is on curve
        let p_i = PodEdwardsPoint(ring[i]);
        if !validate_edwards(&p_i) {
            log!("Invalid point at index");
            return Err(RdpError::InvalidPoint.into());
        }

        // Get response scalar
        let s_i = signature.responses[i];

        // Compute H_p(P_i) - hash public key to point for key image
        let hp_i = hash_to_point_for_key_image(&ring[i])?;

        // Compute L_i = s_i * G + c_i * P_i
        let l_i = compute_l(&s_i, &c, &ring[i])?;

        // Compute R_i = s_i * H_p(P_i) + c_i * I
        let r_i = compute_r(&s_i, &hp_i, &c, &signature.key_image)?;

        // Compute next challenge
        c = compute_challenge(message, ring, &signature.key_image, &l_i, &r_i, i);
    }

    // Verify that we got back to the original challenge
    if c != signature.c {
        log!("Ring signature verification failed");
        return Err(RdpError::RingVerificationFailed.into());
    }

    Ok(())
}

/// Compute L_i = s_i * G + c_i * P_i
#[inline]
fn compute_l(
    s: &[u8; SCALAR_SIZE],
    c: &[u8; SCALAR_SIZE],
    p: &[u8; POINT_SIZE],
) -> RdpResult<[u8; POINT_SIZE]> {
    let basepoint = PodEdwardsPoint(BASEPOINT);
    let point_p = PodEdwardsPoint(*p);
    let scalar_s = PodScalar(*s);
    let scalar_c = PodScalar(*c);

    // s * G
    let sg = multiply_edwards(&scalar_s, &basepoint)
        .ok_or(ProgramError::from(RdpError::CurveOperationFailed))?;

    // c * P
    let cp = multiply_edwards(&scalar_c, &point_p)
        .ok_or(ProgramError::from(RdpError::CurveOperationFailed))?;

    // s * G + c * P
    let result = add_edwards(&sg, &cp)
        .ok_or(ProgramError::from(RdpError::CurveOperationFailed))?;

    Ok(result.0)
}

/// Compute R_i = s_i * H_p(P_i) + c_i * I
#[inline]
fn compute_r(
    s: &[u8; SCALAR_SIZE],
    hp: &[u8; POINT_SIZE],
    c: &[u8; SCALAR_SIZE],
    key_image: &[u8; POINT_SIZE],
) -> RdpResult<[u8; POINT_SIZE]> {
    let point_hp = PodEdwardsPoint(*hp);
    let point_i = PodEdwardsPoint(*key_image);
    let scalar_s = PodScalar(*s);
    let scalar_c = PodScalar(*c);

    // s * H_p
    let shp = multiply_edwards(&scalar_s, &point_hp)
        .ok_or(ProgramError::from(RdpError::CurveOperationFailed))?;

    // c * I
    let ci = multiply_edwards(&scalar_c, &point_i)
        .ok_or(ProgramError::from(RdpError::CurveOperationFailed))?;

    // s * H_p + c * I
    let result = add_edwards(&shp, &ci)
        .ok_or(ProgramError::from(RdpError::CurveOperationFailed))?;

    Ok(result.0)
}

/// Hash public key to point for key image derivation
fn hash_to_point_for_key_image(public_key: &[u8; 32]) -> RdpResult<[u8; POINT_SIZE]> {
    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_KEY_IMAGE);
    hasher.update(public_key);
    let result = hasher.finalize();

    let mut data = [0u8; 64];
    data.copy_from_slice(&result);

    hash_to_point(&data)
}

/// Hash to point using try-and-increment
fn hash_to_point(data: &[u8]) -> RdpResult<[u8; POINT_SIZE]> {
    let mut counter: u32 = 0;

    loop {
        let mut hasher = Sha512::new();
        hasher.update(DOMAIN_HASH_TO_POINT);
        hasher.update(data);
        hasher.update(&counter.to_le_bytes());
        let result = hasher.finalize();

        let mut point_bytes = [0u8; 32];
        point_bytes.copy_from_slice(&result[..32]);
        point_bytes[31] &= 0x7f;

        let candidate = PodEdwardsPoint(point_bytes);
        if validate_edwards(&candidate) {
            // Multiply by cofactor 8
            let eight = PodScalar([
                8u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]);
            if let Some(cleared) = multiply_edwards(&eight, &candidate) {
                if cleared.0 != IDENTITY {
                    return Ok(cleared.0);
                }
            }
        }

        counter += 1;
        if counter >= 1000 {
            return Err(RdpError::CurveOperationFailed.into());
        }
    }
}

/// Compute challenge hash
fn compute_challenge(
    message: &[u8],
    ring: &[[u8; POINT_SIZE]],
    key_image: &[u8; POINT_SIZE],
    l: &[u8; POINT_SIZE],
    r: &[u8; POINT_SIZE],
    index: usize,
) -> [u8; SCALAR_SIZE] {
    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_RING_CHALLENGE);

    // Length-prefix message
    hasher.update(&(message.len() as u32).to_le_bytes());
    hasher.update(message);

    // Ring bytes
    let ring_len = ring.len() * POINT_SIZE;
    hasher.update(&(ring_len as u32).to_le_bytes());
    for pk in ring {
        hasher.update(pk);
    }

    // Key image
    hasher.update(&(POINT_SIZE as u32).to_le_bytes());
    hasher.update(key_image);

    // L and R
    hasher.update(&(POINT_SIZE as u32).to_le_bytes());
    hasher.update(l);
    hasher.update(&(POINT_SIZE as u32).to_le_bytes());
    hasher.update(r);

    // Index
    hasher.update(&4u32.to_le_bytes());
    hasher.update(&(index as u32).to_le_bytes());

    let result = hasher.finalize();

    // Simple scalar reduction: take first 32 bytes, mask top bits
    let mut output = [0u8; 32];
    output.copy_from_slice(&result[..32]);
    output[31] &= 0x0f;
    output
}
