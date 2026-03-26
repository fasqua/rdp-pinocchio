/**
 * RDP Pinocchio - Double Spend Test for Ring Size 16
 * 
 * Test that the same key image cannot be used twice
 */

import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  SystemProgram,
  sendAndConfirmTransaction,
  LAMPORTS_PER_SOL,
  SYSVAR_CLOCK_PUBKEY,
  ComputeBudgetProgram,
} from '@solana/web3.js';
import * as fs from 'fs';

const PROGRAM_ID = new PublicKey('3HJBh4KFTzUjU8avv19KbezjZiekVbBtV7eraSWCyvab');
const RING_POOL_SIZE = 8918;

const RDP_IX = { 
  Initialize: 0, 
  Deposit: 1, 
  Withdraw: 2, 
  PrepareWithdraw: 3,
  ExecuteWithdraw: 4,
} as const;

function loadKeypair(path: string): Keypair {
  return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(path, 'utf-8'))));
}

function loadTestData(): any {
  return JSON.parse(fs.readFileSync('./e2e-test-data-ring16.json', 'utf-8'));
}

function deriveVaultPDA(ringPool: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([Buffer.from('vault'), ringPool.toBuffer()], PROGRAM_ID);
}

function derivePendingPDA(ringPool: PublicKey, creator: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from('pending'), ringPool.toBuffer(), creator.toBuffer()], 
    PROGRAM_ID
  );
}

function buildInitializeIx(ringPool: PublicKey, authority: PublicKey, denomination: bigint, poolBump: number, vaultBump: number): TransactionInstruction {
  const data = Buffer.alloc(11);
  data.writeUInt8(RDP_IX.Initialize, 0);
  data.writeBigUInt64LE(denomination, 1);
  data.writeUInt8(poolBump, 9);
  data.writeUInt8(vaultBump, 10);
  return new TransactionInstruction({
    keys: [
      { pubkey: ringPool, isSigner: false, isWritable: true },
      { pubkey: authority, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    programId: PROGRAM_ID, data,
  });
}

function buildDepositIx(ringPool: PublicKey, vault: PublicKey, depositor: PublicKey, commitment: Buffer, bulletproof: Buffer): TransactionInstruction {
  const data = Buffer.alloc(1 + 32 + 704);
  data.writeUInt8(RDP_IX.Deposit, 0);
  commitment.copy(data, 1);
  bulletproof.copy(data, 33);
  return new TransactionInstruction({
    keys: [
      { pubkey: ringPool, isSigner: false, isWritable: true },
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: depositor, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: SYSVAR_CLOCK_PUBKEY, isSigner: false, isWritable: false },
    ],
    programId: PROGRAM_ID, data,
  });
}

function buildBulletproof(bp: any): Buffer {
  const bulletproof = Buffer.alloc(704);
  let offset = 0;
  Buffer.from(bp.v_commitment).copy(bulletproof, offset); offset += 32;
  Buffer.from(bp.a).copy(bulletproof, offset); offset += 32;
  Buffer.from(bp.s).copy(bulletproof, offset); offset += 32;
  Buffer.from(bp.t1).copy(bulletproof, offset); offset += 32;
  Buffer.from(bp.t2).copy(bulletproof, offset); offset += 32;
  Buffer.from(bp.tau_x).copy(bulletproof, offset); offset += 32;
  Buffer.from(bp.mu).copy(bulletproof, offset); offset += 32;
  Buffer.from(bp.t_hat).copy(bulletproof, offset); offset += 32;
  for (let i = 0; i < 6; i++) { Buffer.from(bp.ip_l[i]).copy(bulletproof, offset); offset += 32; }
  for (let i = 0; i < 6; i++) { Buffer.from(bp.ip_r[i]).copy(bulletproof, offset); offset += 32; }
  Buffer.from(bp.ip_a).copy(bulletproof, offset); offset += 32;
  Buffer.from(bp.ip_b).copy(bulletproof, offset);
  return bulletproof;
}

function buildPrepareWithdrawIx(
  ringPool: PublicKey, 
  pendingPDA: PublicKey,
  creator: PublicKey,
  pendingBump: number,
  testData: any
): TransactionInstruction {
  const wd = testData.withdraw;
  const ringPubkeys = wd.ring_pubkeys_bytes;
  const ringSize = ringPubkeys.length;
  const amount = BigInt(testData.deposit.amount);
  
  const totalSize = 1 + 1 + (ringSize * 32) + 32 + 8 + 1;
  const data = Buffer.alloc(totalSize);
  let offset = 0;
  
  data.writeUInt8(RDP_IX.PrepareWithdraw, offset); offset += 1;
  data.writeUInt8(ringSize, offset); offset += 1;
  
  for (let i = 0; i < ringSize; i++) {
    Buffer.from(ringPubkeys[i]).copy(data, offset); offset += 32;
  }
  
  Buffer.from(wd.destination_bytes).copy(data, offset); offset += 32;
  data.writeBigUInt64LE(amount, offset); offset += 8;
  data.writeUInt8(pendingBump, offset);

  return new TransactionInstruction({
    keys: [
      { pubkey: ringPool, isSigner: false, isWritable: true },
      { pubkey: pendingPDA, isSigner: false, isWritable: true },
      { pubkey: creator, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    programId: PROGRAM_ID, data,
  });
}

function buildExecuteWithdrawIx(
  ringPool: PublicKey,
  vault: PublicKey,
  destination: PublicKey,
  pendingPDA: PublicKey,
  creator: PublicKey,
  pendingBump: number,
  testData: any,
): TransactionInstruction {
  const wd = testData.withdraw;
  const ringSize = wd.ring_pubkeys_bytes.length;
  
  const totalSize = 1 + 32 + (ringSize * 32) + 32 + 1;
  const data = Buffer.alloc(totalSize);
  let offset = 0;
  
  data.writeUInt8(RDP_IX.ExecuteWithdraw, offset); offset += 1;
  Buffer.from(wd.ring_signature.c_bytes).copy(data, offset); offset += 32;
  
  for (let i = 0; i < ringSize; i++) {
    Buffer.from(wd.ring_signature.responses[i]).copy(data, offset); offset += 32;
  }
  
  Buffer.from(wd.key_image_bytes).copy(data, offset); offset += 32;
  data.writeUInt8(pendingBump, offset);

  return new TransactionInstruction({
    keys: [
      { pubkey: ringPool, isSigner: false, isWritable: true },
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: destination, isSigner: false, isWritable: true },
      { pubkey: pendingPDA, isSigner: false, isWritable: true },
      { pubkey: creator, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    programId: PROGRAM_ID, data,
  });
}

async function main() {
  console.log('='.repeat(70));
  console.log('RDP Pinocchio - Double Spend Test (Ring Size 16)');
  console.log('='.repeat(70));

  const connection = new Connection('https://api.devnet.solana.com', 'confirmed');
  const wallet = loadKeypair(process.env.WALLET_PATH || './wallet.json');
  const testData = loadTestData();

  console.log(`\n✓ Wallet: ${wallet.publicKey.toBase58()}`);

  // Setup: Initialize + Deposit + First Withdraw
  console.log('\n' + '-'.repeat(70));
  console.log('SETUP: Initialize Pool + Deposit + First Withdraw');
  console.log('-'.repeat(70));

  const denomination = BigInt(testData.deposit.amount);
  const ringPoolKeypair = Keypair.generate();
  const [vaultPDA, vaultBump] = deriveVaultPDA(ringPoolKeypair.publicKey);
  const [pendingPDA, pendingBump] = derivePendingPDA(ringPoolKeypair.publicKey, wallet.publicKey);

  // Initialize
  const rentExemption = await connection.getMinimumBalanceForRentExemption(RING_POOL_SIZE);
  const vaultRent = await connection.getMinimumBalanceForRentExemption(0);

  const createPoolIx = SystemProgram.createAccount({
    fromPubkey: wallet.publicKey,
    newAccountPubkey: ringPoolKeypair.publicKey,
    lamports: rentExemption,
    space: RING_POOL_SIZE,
    programId: PROGRAM_ID,
  });

  const initIx = buildInitializeIx(ringPoolKeypair.publicKey, wallet.publicKey, denomination, 0, vaultBump);
  const fundVaultIx = SystemProgram.transfer({ fromPubkey: wallet.publicKey, toPubkey: vaultPDA, lamports: vaultRent });

  const tx1 = new Transaction().add(createPoolIx, initIx, fundVaultIx);
  await sendAndConfirmTransaction(connection, tx1, [wallet, ringPoolKeypair]);
  console.log('  ✓ Pool initialized');

  // Deposit
  const commitment = Buffer.from(testData.deposit.commitment_bytes);
  const bulletproof = buildBulletproof(testData.withdraw.bulletproof);
  const computeIx = ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 });
  const depositIx = buildDepositIx(ringPoolKeypair.publicKey, vaultPDA, wallet.publicKey, commitment, bulletproof);

  const tx2 = new Transaction().add(computeIx, depositIx);
  await sendAndConfirmTransaction(connection, tx2, [wallet]);
  console.log('  ✓ Deposit complete');

  // First Withdraw (should succeed)
  const prepareIx = buildPrepareWithdrawIx(ringPoolKeypair.publicKey, pendingPDA, wallet.publicKey, pendingBump, testData);
  const tx3 = new Transaction().add(prepareIx);
  await sendAndConfirmTransaction(connection, tx3, [wallet]);
  console.log('  ✓ PrepareWithdraw complete');

  const destinationPubkey = new PublicKey(Buffer.from(testData.withdraw.destination_bytes));
  const destRent = await connection.getMinimumBalanceForRentExemption(0);
  const fundDestIx = SystemProgram.transfer({ fromPubkey: wallet.publicKey, toPubkey: destinationPubkey, lamports: destRent });
  
  const executeIx = buildExecuteWithdrawIx(
    ringPoolKeypair.publicKey,
    vaultPDA,
    destinationPubkey,
    pendingPDA,
    wallet.publicKey,
    pendingBump,
    testData
  );

  const tx4 = new Transaction().add(computeIx, fundDestIx, executeIx);
  await sendAndConfirmTransaction(connection, tx4, [wallet]);
  console.log('  ✓ First withdraw SUCCESS');

  // Double Spend Attempt
  console.log('\n' + '-'.repeat(70));
  console.log('TEST: Double Spend Attempt (same key image)');
  console.log('-'.repeat(70));

  // Need to create new PendingWithdraw PDA (old one was closed)
  // Use different creator to get different PDA
  const attacker = Keypair.generate();
  
  // Fund attacker
  const fundAttackerIx = SystemProgram.transfer({
    fromPubkey: wallet.publicKey,
    toPubkey: attacker.publicKey,
    lamports: 0.1 * LAMPORTS_PER_SOL,
  });
  const fundTx = new Transaction().add(fundAttackerIx);
  await sendAndConfirmTransaction(connection, fundTx, [wallet]);

  const [pendingPDA2, pendingBump2] = derivePendingPDA(ringPoolKeypair.publicKey, attacker.publicKey);

  // PrepareWithdraw with attacker
  const prepareIx2Data = (() => {
    const wd = testData.withdraw;
    const ringPubkeys = wd.ring_pubkeys_bytes;
    const ringSize = ringPubkeys.length;
    const amount = BigInt(testData.deposit.amount);
    
    const totalSize = 1 + 1 + (ringSize * 32) + 32 + 8 + 1;
    const data = Buffer.alloc(totalSize);
    let offset = 0;
    
    data.writeUInt8(RDP_IX.PrepareWithdraw, offset); offset += 1;
    data.writeUInt8(ringSize, offset); offset += 1;
    
    for (let i = 0; i < ringSize; i++) {
      Buffer.from(ringPubkeys[i]).copy(data, offset); offset += 32;
    }
    
    Buffer.from(wd.destination_bytes).copy(data, offset); offset += 32;
    data.writeBigUInt64LE(amount, offset); offset += 8;
    data.writeUInt8(pendingBump2, offset);
    
    return data;
  })();

  const prepareIx2 = new TransactionInstruction({
    keys: [
      { pubkey: ringPoolKeypair.publicKey, isSigner: false, isWritable: true },
      { pubkey: pendingPDA2, isSigner: false, isWritable: true },
      { pubkey: attacker.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    programId: PROGRAM_ID,
    data: prepareIx2Data,
  });

  const tx5 = new Transaction().add(prepareIx2);
  await sendAndConfirmTransaction(connection, tx5, [attacker]);
  console.log('  ✓ PrepareWithdraw (attempt 2) complete');

  // Try ExecuteWithdraw with same key image
  const executeIx2 = (() => {
    const wd = testData.withdraw;
    const ringSize = wd.ring_pubkeys_bytes.length;
    
    const totalSize = 1 + 32 + (ringSize * 32) + 32 + 1;
    const data = Buffer.alloc(totalSize);
    let offset = 0;
    
    data.writeUInt8(RDP_IX.ExecuteWithdraw, offset); offset += 1;
    Buffer.from(wd.ring_signature.c_bytes).copy(data, offset); offset += 32;
    
    for (let i = 0; i < ringSize; i++) {
      Buffer.from(wd.ring_signature.responses[i]).copy(data, offset); offset += 32;
    }
    
    Buffer.from(wd.key_image_bytes).copy(data, offset); offset += 32;
    data.writeUInt8(pendingBump2, offset);
    
    return data;
  })();

  const executeIx2Inst = new TransactionInstruction({
    keys: [
      { pubkey: ringPoolKeypair.publicKey, isSigner: false, isWritable: true },
      { pubkey: vaultPDA, isSigner: false, isWritable: true },
      { pubkey: destinationPubkey, isSigner: false, isWritable: true },
      { pubkey: pendingPDA2, isSigner: false, isWritable: true },
      { pubkey: attacker.publicKey, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    programId: PROGRAM_ID,
    data: executeIx2,
  });

  try {
    const tx6 = new Transaction().add(computeIx, executeIx2Inst);
    await sendAndConfirmTransaction(connection, tx6, [attacker]);
    console.log('  ✗ Double spend SUCCEEDED (BUG!)');
  } catch (err: any) {
    const logs = err.transactionLogs || [];
    const hasKeyImageSpent = logs.some((log: string) => log.includes('0x1790'));
    
    if (hasKeyImageSpent) {
      console.log('  ✓ Double spend REJECTED with KeyImageAlreadySpent (0x1790)');
      console.log('\n' + '='.repeat(70));
      console.log('RESULT: Double-spend protection WORKING ✓');
      console.log('='.repeat(70));
    } else {
      console.log(`  ✗ Rejected but wrong error: ${err.message}`);
      console.log('  Logs:', logs);
    }
  }
}

main().catch(console.error);
