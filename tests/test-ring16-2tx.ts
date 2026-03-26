/**
 * RDP Pinocchio - Ring Size 16 with 2-TX Withdraw
 * 
 * TX1: PrepareWithdraw - create PendingWithdraw PDA with ring pubkeys
 * TX2: ExecuteWithdraw - verify signature, transfer, close PDA
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
const PENDING_SIZE = 632;

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

/**
 * TX1: PrepareWithdraw
 * Layout: disc(1) + ring_size(1) + ring_pubkeys(N*32) + destination(32) + amount(8) + bump(1)
 */
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
  
  // disc(1) + ring_size(1) + ring_pubkeys(N*32) + destination(32) + amount(8) + bump(1)
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

/**
 * TX2: ExecuteWithdraw  
 * Layout: disc(1) + c(32) + responses(N*32) + key_image(32) + pending_bump(1)
 */
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
  
  // disc(1) + c(32) + responses(N*32) + key_image(32) + pending_bump(1)
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

async function getCU(connection: Connection, signature: string): Promise<number | null> {
  const tx = await connection.getTransaction(signature, { maxSupportedTransactionVersion: 0 });
  return tx?.meta?.computeUnitsConsumed ?? null;
}

async function main() {
  console.log('='.repeat(70));
  console.log('RDP Pinocchio - Ring Size 16 (2-TX Withdraw)');
  console.log('='.repeat(70));

  const connection = new Connection('https://api.devnet.solana.com', 'confirmed');
  const wallet = loadKeypair(process.env.WALLET_PATH || './wallet.json');
  const testData = loadTestData();

  const startBalance = await connection.getBalance(wallet.publicKey);
  console.log(`\n✓ Wallet: ${wallet.publicKey.toBase58()}`);
  console.log(`✓ Balance: ${startBalance / LAMPORTS_PER_SOL} SOL`);
  console.log(`✓ Ring size: ${testData.withdraw.ring_size}`);

  // TEST 1: Initialize Pool
  console.log('\n' + '-'.repeat(70));
  console.log('TEST 1: Initialize Pool');
  console.log('-'.repeat(70));

  const denomination = BigInt(testData.deposit.amount);
  const ringPoolKeypair = Keypair.generate();
  const [vaultPDA, vaultBump] = deriveVaultPDA(ringPoolKeypair.publicKey);
  const [pendingPDA, pendingBump] = derivePendingPDA(ringPoolKeypair.publicKey, wallet.publicKey);
  
  console.log(`  Pool: ${ringPoolKeypair.publicKey.toBase58()}`);
  console.log(`  Vault: ${vaultPDA.toBase58()}`);
  console.log(`  Pending PDA: ${pendingPDA.toBase58()}`);

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
  const sig1 = await sendAndConfirmTransaction(connection, tx1, [wallet, ringPoolKeypair]);
  
  await new Promise(r => setTimeout(r, 2000));
  const cu1 = await getCU(connection, sig1);
  
  console.log(`  ✓ TX: ${sig1}`);
  console.log(`  ✓ CU: ${cu1?.toLocaleString()}`);

  // TEST 2: Deposit with Bulletproof
  console.log('\n' + '-'.repeat(70));
  console.log('TEST 2: Deposit with Bulletproof');
  console.log('-'.repeat(70));

  const commitment = Buffer.from(testData.deposit.commitment_bytes);
  const bulletproof = buildBulletproof(testData.withdraw.bulletproof);
  const computeIx = ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 });
  const depositIx = buildDepositIx(ringPoolKeypair.publicKey, vaultPDA, wallet.publicKey, commitment, bulletproof);

  const tx2 = new Transaction().add(computeIx, depositIx);
  const sig2 = await sendAndConfirmTransaction(connection, tx2, [wallet]);
  
  await new Promise(r => setTimeout(r, 2000));
  const cu2 = await getCU(connection, sig2);
  
  console.log(`  ✓ TX: ${sig2}`);
  console.log(`  ✓ CU: ${cu2?.toLocaleString()} (Bulletproof verification)`);

  // TEST 3: PrepareWithdraw (TX1 of 2)
  console.log('\n' + '-'.repeat(70));
  console.log('TEST 3: PrepareWithdraw (TX1 - create PendingWithdraw PDA)');
  console.log('-'.repeat(70));

  const prepareIx = buildPrepareWithdrawIx(
    ringPoolKeypair.publicKey, 
    pendingPDA, 
    wallet.publicKey, 
    pendingBump,
    testData
  );
  
  const tx3 = new Transaction().add(prepareIx);
  const sig3 = await sendAndConfirmTransaction(connection, tx3, [wallet]);
  
  await new Promise(r => setTimeout(r, 2000));
  const cu3 = await getCU(connection, sig3);
  
  // Verify PDA created
  const pendingInfo = await connection.getAccountInfo(pendingPDA);
  console.log(`  ✓ TX: ${sig3}`);
  console.log(`  ✓ CU: ${cu3?.toLocaleString()}`);
  console.log(`  ✓ PendingWithdraw PDA created: ${pendingInfo ? 'YES' : 'NO'}`);
  console.log(`  ✓ PDA size: ${pendingInfo?.data.length} bytes`);

  // TEST 4: ExecuteWithdraw (TX2 of 2)
  console.log('\n' + '-'.repeat(70));
  console.log('TEST 4: ExecuteWithdraw (TX2 - verify & transfer)');
  console.log('-'.repeat(70));

  const destinationPubkey = new PublicKey(Buffer.from(testData.withdraw.destination_bytes));
  
  // Fund destination with rent
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
  const sig4 = await sendAndConfirmTransaction(connection, tx4, [wallet]);
  
  await new Promise(r => setTimeout(r, 2000));
  const cu4 = await getCU(connection, sig4);
  
  const destBalance = await connection.getBalance(destinationPubkey);
  const vaultBalance = await connection.getBalance(vaultPDA);
  
  // Verify PDA closed
  const pendingInfoAfter = await connection.getAccountInfo(pendingPDA);
  
  console.log(`  ✓ TX: ${sig4}`);
  console.log(`  ✓ CU: ${cu4?.toLocaleString()} (Ring sig 16 verification)`);
  console.log(`  ✓ Destination: ${destBalance / LAMPORTS_PER_SOL} SOL`);
  console.log(`  ✓ Vault remaining: ${vaultBalance / LAMPORTS_PER_SOL} SOL`);
  console.log(`  ✓ PendingWithdraw PDA closed: ${!pendingInfoAfter ? 'YES' : 'NO'}`);

  // Summary
  console.log('\n' + '='.repeat(70));
  console.log('SUMMARY - Ring Size 16 (2-TX Withdraw)');
  console.log('='.repeat(70));
  console.log(`\n  Privacy: 93.75% (1 in 16 anonymity set)`);
  console.log(`\n  Solana Explorer Links:`);
  console.log(`    Initialize:      https://explorer.solana.com/tx/${sig1}?cluster=devnet`);
  console.log(`    Deposit:         https://explorer.solana.com/tx/${sig2}?cluster=devnet`);
  console.log(`    PrepareWithdraw: https://explorer.solana.com/tx/${sig3}?cluster=devnet`);
  console.log(`    ExecuteWithdraw: https://explorer.solana.com/tx/${sig4}?cluster=devnet`);
  console.log(`\n  Compute Units:`);
  console.log(`    Initialize:      ${cu1?.toLocaleString()} CU`);
  console.log(`    Deposit:         ${cu2?.toLocaleString()} CU (Bulletproof)`);
  console.log(`    PrepareWithdraw: ${cu3?.toLocaleString()} CU`);
  console.log(`    ExecuteWithdraw: ${cu4?.toLocaleString()} CU (Ring sig 16)`);
  console.log(`    Total Withdraw:  ${((cu3 || 0) + (cu4 || 0)).toLocaleString()} CU`);
  
  const endBalance = await connection.getBalance(wallet.publicKey);
  console.log(`\n  SOL Used: ${((startBalance - endBalance) / LAMPORTS_PER_SOL).toFixed(6)} SOL`);
  console.log('='.repeat(70));
}

main().catch(console.error);
