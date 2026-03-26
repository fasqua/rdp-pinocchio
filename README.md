<div align="center">

# Ring Diffusion Protocol (RDP) — Pinocchio Edition

### Privacy-Preserving Transactions on Solana — Optimized for Performance

[![Solana](https://img.shields.io/badge/Solana-Devnet-blueviolet?style=for-the-badge&logo=solana)](https://solana.com)
[![Rust](https://img.shields.io/badge/Rust-1.70+-orange?style=for-the-badge&logo=rust)](https://rust-lang.org)
[![Pinocchio](https://img.shields.io/badge/Pinocchio-Framework-pink?style=for-the-badge)](https://github.com/anza-xyz/pinocchio)
[![License](https://img.shields.io/badge/License-Apache_2.0-green?style=for-the-badge)](LICENSE)

---

*Built by KausaLayer — Pinocchio rewrite for 77% smaller binary & lower CU*

</div>

---

## ⚠️ Security Notice

This software is deployed on **Solana Devnet only**. Do not use with real funds. For research and testing purposes only.

---

## Table of Contents

- [What is RDP Pinocchio?](#what-is-rdp-pinocchio)
- [Why Pinocchio?](#why-pinocchio)
- [How It Works](#how-it-works)
- [Technical Specifications](#technical-specifications)
- [Cryptographic Primitives](#cryptographic-primitives)
- [Program Instructions](#program-instructions)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Test Results](#test-results)
- [FAQ](#faq)

---

## What is RDP Pinocchio?

**Ring Diffusion Protocol (Pinocchio Edition)** is a performance-optimized rewrite of RDP using the Pinocchio framework instead of Anchor. It enables private transactions on Solana where users deposit SOL into a shared pool and withdraw to a completely different address — with **no on-chain link** between deposit and withdrawal.

### The Problem

Every Solana transaction is permanently public:
- Your wallet balance is visible to everyone
- Every transfer is traceable
- Your entire financial history is on display

### The Solution

RDP breaks the on-chain link using cryptographic primitives:

| Layer | Primitive | Protection |
|:-----:|-----------|------------|
| 1 | **Ring Signature (CLSAG)** | Hides which deposit is being spent |
| 2 | **Bulletproof** | Proves amount validity without revealing it |
| 3 | **Key Image** | Prevents double-spending |
| 4 | **Pedersen Commitment** | Hides the transaction amount |

---

## Why Pinocchio?

### Anchor vs Pinocchio Comparison

| Metric | Anchor Version | Pinocchio Version | Improvement |
|--------|----------------|-------------------|-------------|
| **Binary Size** | 740 KB | 169 KB | **77% smaller** |
| **Withdraw TX** | 6 phases | 1-2 TX | **Simpler flow** |
| **Dependencies** | Heavy runtime | Zero-copy | **Minimal overhead** |

### Key Improvements

1. **Single/Dual TX Withdraw**: Ring size ≤8 uses single TX, ring size 16 uses only 2 TX (vs 6 phases in Anchor)
2. **Zero-Copy State**: Direct memory access without serialization overhead
3. **Optimized Crypto**: Inline scalar reduction and point operations

---

## How It Works

### Deposit Flow
```
┌─────────────┐                                    ┌─────────────────┐
│    USER     │                                    │   RDP PROGRAM   │
└──────┬──────┘                                    └────────┬────────┘
       │                                                    │
       │  1. Generate Pedersen commitment: C = v*G + r*H    │
       │  2. Generate Bulletproof for range [0, 2⁶⁴)        │
       │  3. Store blinding factor r securely (CRITICAL!)   │
       │                                                    │
       │  4. deposit(commitment, bulletproof)               │
       │  ─────────────────────────────────────────────────►│
       │                                                    │
       │                    5. Verify Bulletproof (~341K CU)│
       │                    6. Store commitment in pool     │
       │                    7. Lock SOL in vault PDA        │
       │                                                    │
       │  8. Deposit confirmed                              │
       │  ◄─────────────────────────────────────────────────│
       ▼                                                    ▼
```

### Withdraw Flow

#### Ring Size ≤ 8 (Single TX)
```
┌────────────────────────────────────────────────────────────────────────┐
│                    SINGLE TX WITHDRAW (Ring ≤ 8)                       │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  withdraw(ring_pubkeys, ring_signature, key_image, destination)        │
│  └── Verify CLSAG ring signature                                       │
│  └── Check key image not spent (double-spend prevention)               │
│  └── Record key image as spent                                         │
│  └── Transfer SOL from vault to destination                            │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

#### Ring Size 16 (2-TX)
```
┌────────────────────────────────────────────────────────────────────────┐
│                      2-TX WITHDRAW (Ring 16)                           │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  TX1: prepare_withdraw                                                 │
│  └── Create PendingWithdraw PDA                                        │
│  └── Store ring pubkeys (16 × 32 = 512 bytes)                          │
│  └── Store destination + amount                                        │
│                                                                        │
│  TX2: execute_withdraw                                                 │
│  └── Read ring from PDA                                                │
│  └── Verify CLSAG ring signature (~1.3M CU)                            │
│  └── Check key image not spent                                         │
│  └── Transfer SOL to destination                                       │
│  └── Close PDA (refund rent to creator)                                │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Technical Specifications

### Deployment Information

| Parameter | Value |
|-----------|-------|
| **Program ID** | `3HJBh4KFTzUjU8avv19KbezjZiekVbBtV7eraSWCyvab` |
| **Network** | Solana Devnet |
| **Binary Size** | 169 KB |

### Protocol Parameters

| Parameter | Value |
|-----------|-------|
| Max Ring Size | 16 |
| Max Commitments | 16 per pool |
| Max Spent Key Images | 256 per pool |
| Pool Account Size | 8,918 bytes |

### Privacy Levels

| Ring Size | Anonymity Set | Privacy Level | TX Architecture |
|-----------|---------------|---------------|-----------------|
| 4 | 1-in-4 | 75% | Single TX |
| 8 | 1-in-8 | 87.5% | Single TX |
| 16 | 1-in-16 | 93.75% | 2-TX |

---

## Cryptographic Primitives

### 1. Ring Signatures (CLSAG)

Compact Linkable Spontaneous Anonymous Group signatures. More efficient than LSAG with smaller signature size.

**Verification formula:**
```
For each i in ring:
  L_i = s_i * G + c_i * P_i
  R_i = s_i * H_p(P_i) + c_i * I
  c_{i+1} = H(m || L_i || R_i)
```

### 2. Bulletproofs (Range Proofs)

Zero-knowledge proofs that a committed value is within valid range [0, 2⁶⁴) without revealing the value.

**Components:**
- V commitment, A, S, T1, T2 points
- tau_x, mu, t_hat scalars  
- Inner product proof (L, R vectors + a, b scalars)
- Total size: 704 bytes

### 3. Key Images (Double-Spend Prevention)
```
Key Image I = x * H_p(P)
```

Each private key `x` produces a unique, deterministic key image. Once recorded on-chain, that deposit cannot be spent again.

### 4. Pedersen Commitments
```
C = v*G + r*H
```

Commits to value `v` with blinding factor `r`. Computationally hiding and binding.

---

## Program Instructions

| IX | Name | Description | Accounts |
|----|------|-------------|----------|
| 0 | `initialize` | Create ring pool with denomination | pool, authority, system |
| 1 | `deposit` | Add commitment + bulletproof | pool, vault, depositor, system, clock |
| 2 | `withdraw` | Single-TX withdraw (ring ≤ 8) | pool, vault, destination, system |
| 3 | `prepare_withdraw` | TX1: Store ring in PDA | pool, pending_pda, creator, system |
| 4 | `execute_withdraw` | TX2: Verify + transfer | pool, vault, dest, pending, creator, system |

### Instruction Data Layouts

**Initialize (11 bytes):**
```
[0] discriminator
[1-8] denomination (u64 LE)
[9] pool_bump
[10] vault_bump
```

**Deposit (737 bytes):**
```
[0] discriminator
[1-32] commitment (32 bytes)
[33-736] bulletproof (704 bytes)
```

**Withdraw (varies by ring size):**
```
[0] discriminator
[1] ring_size
[2..] ring_pubkeys (N × 32)
[..] c (32 bytes)
[..] responses (N × 32)
[..] key_image (32 bytes)
[..] amount (8 bytes)
```

---

## Quick Start

### Prerequisites

- Rust 1.70+
- Solana CLI 1.18+
- Node.js 18+

### Build
```bash
git clone <repository-url>
cd rdp-pinocchio
cargo build-sbf
```

### Deploy
```bash
solana program deploy \
  --keypair <KEYPAIR> \
  --program-id target/deploy/rdp_pinocchio-keypair.json \
  target/deploy/rdp_pinocchio.so \
  --url devnet
```

### Run Tests
```bash
cd tests
npm install

# Ring size 16 (2-TX) test
npx ts-node --esm test-ring16-2tx.ts

# Double-spend protection test
npx ts-node --esm test-double-spend-ring16.ts
```

---

## Project Structure
```
rdp-pinocchio/
├── src/
│   ├── crypto/
│   │   ├── ring_verifier.rs        # CLSAG signature verification
│   │   ├── bulletproofs_verifier.rs # Range proof verification
│   │   ├── scalar_reduce.rs        # 512-bit to 256-bit reduction
│   │   ├── merkle_verifier.rs      # Merkle proof verification
│   │   └── types.rs                # Crypto data structures
│   ├── state/
│   │   ├── ring_pool.rs            # Main pool state (8,918 bytes)
│   │   └── pending_withdraw.rs     # 2-TX withdraw state (632 bytes)
│   ├── instructions/
│   │   ├── initialize.rs           # Pool initialization
│   │   ├── deposit.rs              # Deposit with bulletproof
│   │   ├── withdraw.rs             # Single-TX withdraw
│   │   ├── prepare_withdraw.rs     # TX1 of 2-TX withdraw
│   │   └── execute_withdraw.rs     # TX2 of 2-TX withdraw
│   ├── entrypoint.rs               # Program entrypoint
│   ├── processor.rs                # Instruction router
│   ├── error.rs                    # Error definitions
│   └── lib.rs                      # Library exports
├── tests/
│   ├── test-ring16-2tx.ts          # Ring 16 (2-TX) test
│   └── test-double-spend-ring16.ts # Double-spend test (ring 16)
└── Cargo.toml
```

---

## Test Results

| Test | Ring Size | Status | TX Hash |
|------|-----------|--------|--------|
| E2E 2-TX | 16 | ✅ PASS | [View](https://explorer.solana.com/tx/5HmXsTiXPVfSeaueztha5NDimWReMwFNYCRZoxjhc3dVTrE1cC2HA922dPzVb4X2zWSohHLqXeLoZrwSUhSszRRM?cluster=devnet) |
| Double-spend | 16 | ✅ REJECTED | KeyImageAlreadySpent (0x1790) |

### Compute Unit Usage (Ring 16)

| Operation | CU |
|-----------|------:|
| Initialize | 2,805 |
| Deposit (Bulletproof) | 341,011 |
| PrepareWithdraw (TX1) | 4,559 |
| ExecuteWithdraw (TX2) | 1,316,736 |
| **Total Withdraw** | **1,321,295** |

---

## FAQ

### Why Pinocchio instead of Anchor?

Pinocchio produces significantly smaller binaries (77% reduction) and allows fine-grained control over compute units. Essential for crypto-heavy operations like ring signature verification.

### Why 2 transactions for ring size 16?

Solana's 1,232-byte transaction limit. Ring size 16 requires:
- 16 × 32 = 512 bytes for ring pubkeys
- 16 × 32 = 512 bytes for responses
- 32 bytes for c, 32 bytes for key_image

Total exceeds limit, so we split into PrepareWithdraw (store ring) + ExecuteWithdraw (verify + transfer).

### What if I lose my blinding factor?

Funds are lost forever. There is no recovery mechanism. Store your secret securely.


---

## Contributing

Contributions welcome. Priority areas:
- Security review
- CU optimization
- Additional test coverage
- Frontend integration

---

## License

Apache License 2.0

---

<div align="center">

*Ring Diffusion Protocol — Privacy without trust.*

*Built by KausaLayer*

</div>
