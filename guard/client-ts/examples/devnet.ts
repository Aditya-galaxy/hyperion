// Hyperion Guard on Solana devnet, from TypeScript: the same six scenes as
// guard/demo/solana_devnet.py, against a hosted Guard and the deployed vault
// program. Every transaction is real and printed with an explorer link.
//
//   node examples/devnet.ts
//
//   [HYPERION_GUARD_URL=https://hyperion-guard-dijsyl2kwq-uc.a.run.app]
//   [SOLANA_RPC_URL=https://api.devnet.solana.com]
//   [SOLANA_KEYPAIR=~/.config/solana/id.json]      the owner; pays about 0.01 SOL a run
//   [HYPERION_VAULT_PROGRAM_ID=9btLSADcT2u3M1HnC4cdkV4HiN662bqmhHYvevaSragq]

import { readFileSync } from "node:fs";
import { homedir } from "node:os";

import { Connection, Keypair, PublicKey, SystemProgram, Transaction } from "@solana/web3.js";
import type { TransactionInstruction } from "@solana/web3.js";
import nacl from "tweetnacl";

import { GuardClient, GuardRefused, initializeIx, killIx, transferSolIx, vaultAddress, withdrawIx } from "../src/index.ts";

const GUARD_URL = process.env.HYPERION_GUARD_URL ?? "https://hyperion-guard-dijsyl2kwq-uc.a.run.app";
const RPC = process.env.SOLANA_RPC_URL ?? "https://api.devnet.solana.com";
const PROGRAM = new PublicKey(process.env.HYPERION_VAULT_PROGRAM_ID ?? "9btLSADcT2u3M1HnC4cdkV4HiN662bqmhHYvevaSragq");
const KEYPAIR = (process.env.SOLANA_KEYPAIR ?? "~/.config/solana/id.json").replace(/^~/, homedir());
const SOL = 1_000_000_000;
const WSOL = "So11111111111111111111111111111111111111112";
const ERRORS: Record<number, string> = { 3: "MissingGuardCoSignature", 4: "VaultKilled", 5: "OverCap", 6: "ProgramNotAllowed" };

const connection = new Connection(RPC, "confirmed");
const link = (signature: string) => `https://explorer.solana.com/tx/${signature}?cluster=devnet`;
const scene = (n: number, title: string) => console.log(`\n── ${n}. ${title} ${"─".repeat(Math.max(0, 66 - title.length))}`);

async function build(payer: PublicKey, ...instructions: TransactionInstruction[]): Promise<Transaction> {
  const { blockhash } = await connection.getLatestBlockhash();
  return new Transaction({ feePayer: payer, recentBlockhash: blockhash }).add(...instructions);
}

/** Send without preflight, so a refused transaction is recorded on-chain too. Returns its error, if any. */
async function send(tx: Transaction): Promise<{ signature: string; error: string | null }> {
  const signature = await connection.sendRawTransaction(tx.serialize({ requireAllSignatures: false }), { skipPreflight: true });
  for (let i = 0; i < 60; i++) {
    const status = (await connection.getSignatureStatuses([signature])).value[0];
    if (status?.confirmationStatus === "confirmed" || status?.confirmationStatus === "finalized") {
      const custom = (status.err as { InstructionError?: [number, { Custom?: number }] } | null)?.InstructionError?.[1]?.Custom;
      const error = status.err ? (custom !== undefined ? `Custom(${custom}) ${ERRORS[custom] ?? ""}`.trim() : JSON.stringify(status.err)) : null;
      return { signature, error };
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`${signature} wasn't confirmed in 60 s`);
}

async function solPrice(): Promise<number> {
  const res = await fetch(`https://lite-api.jup.ag/price/v3?ids=${WSOL}`, { headers: { "user-agent": "hyperion-guard" } });
  return ((await res.json()) as Record<string, { usdPrice: number }>)[WSOL]!.usdPrice;
}

const owner = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(KEYPAIR, "utf8"))));
const agent = Keypair.generate();
const guardian = Keypair.generate();
const merchant = Keypair.generate().publicKey;

const guard = new GuardClient(GUARD_URL);
const guardKey = await guard.cosignerKey();
const [vault] = vaultAddress(PROGRAM, owner.publicKey, agent.publicKey);
const price = await solPrice();
// worth 0.0333 SOL, so a 0.02 SOL payment fits and a 0.04 SOL one doesn't, whatever SOL is worth today
const capUsd = Math.round((price / 30) * 100) / 100;
const usd = (lamports: number) => `$${((lamports / SOL) * price).toFixed(2)}`;
const pay = (lamports: number) => transferSolIx(PROGRAM, vault, agent.publicKey, guardKey, merchant, lamports);

console.log(`client    TypeScript (hyperion-guard-client)
program   ${PROGRAM.toBase58()}
owner     ${owner.publicKey.toBase58()}
agent     ${agent.publicKey.toBase58()}
guardian  ${guardian.publicKey.toBase58()}
Guard     ${guardKey.toBase58()}  (${GUARD_URL})
vault     ${vault.toBase58()}
merchant  ${merchant.toBase58()}
SOL       $${price.toFixed(2)}`);

scene(1, "The owner opens a vault for the agent and funds it");
{
  const tx = await build(
    owner.publicKey,
    initializeIx(PROGRAM, owner.publicKey, agent.publicKey, { guardian: guardian.publicKey, guard: guardKey, maxLamportsPerTx: SOL / 20 }),
    SystemProgram.transfer({ fromPubkey: owner.publicKey, toPubkey: vault, lamports: SOL / 10 }),            // the agent's working money
    SystemProgram.transfer({ fromPubkey: owner.publicKey, toPubkey: agent.publicKey, lamports: SOL / 100 }), // the agent's own fees
  );
  tx.sign(owner);
  const { signature, error } = await send(tx);
  if (error) throw new Error(error);
  const now = Math.floor(Date.now() / 1000);                        // version and nonce only need to go up
  await guard.setPolicy(
    { agentId: `devnet-demo-ts-${owner.publicKey.toBase58().slice(0, 8)}`, agent: agent.publicKey, owner: owner.publicKey,
      maxOrderNotionalUsd: capUsd, maxSlippageBps: 100, policyVersion: now, nonce: now, allowedPrograms: [PROGRAM], vaultAddress: vault },
    (message) => nacl.sign.detached(message, owner.secretKey),
  );
  console.log(`   vault holds ${((await connection.getBalance(vault)) / SOL).toFixed(4)} SOL; on-chain cap 0.05 SOL a transaction; Guard policy $${capUsd.toFixed(2)} an order\n   ${link(signature)}`);
}
const agentId = `devnet-demo-ts-${owner.publicKey.toBase58().slice(0, 8)}`;

scene(2, "A normal payment: the Guard co-signs, the vault pays");
{
  const tx = await build(agent.publicKey, pay(SOL / 50));
  tx.partialSign(agent);
  await guard.checkAndCosign(agentId, tx);
  const { signature, error } = await send(tx);
  if (error) throw new Error(error);
  console.log(`   Guard: APPROVED (${usd(SOL / 50)} of a $${capUsd.toFixed(2)} cap)\n   merchant received ${((await connection.getBalance(merchant)) / SOL).toFixed(4)} SOL\n   ${link(signature)}`);
}

scene(3, "The agent goes around the Guard: the program refuses on-chain");
{
  const ix = pay(SOL / 50);
  ix.keys[1]!.isSigner = false;                                     // the Guard is named but hasn't signed
  const tx = await build(agent.publicKey, ix);
  tx.sign(agent);
  const { signature, error } = await send(tx);
  if (!error) throw new Error("the program accepted a transfer without the Guard");
  console.log(`   failed on-chain: ${error}\n   merchant still has ${((await connection.getBalance(merchant)) / SOL).toFixed(4)} SOL\n   ${link(signature)}`);
}

scene(4, "An order over the dollar cap: the Guard won't sign");
{
  const tx = await build(agent.publicKey, pay(SOL / 25));           // under the on-chain cap, over the policy's
  tx.partialSign(agent);
  try {
    await guard.checkAndCosign(agentId, tx);
    throw new Error("the Guard signed an order over the cap");
  } catch (e) {
    if (!(e instanceof GuardRefused)) throw e;
    console.log(`   Guard: ${e.verdict.status}\n   ${e.verdict.violation_details}\n   no signature, so nothing to send`);
  }
}

scene(5, "The guardian kills the vault: an approved transfer is refused");
{
  const approved = await build(agent.publicKey, pay(SOL / 100));
  approved.partialSign(agent);
  await guard.checkAndCosign(agentId, approved);                    // approved before the kill
  const kill = await build(owner.publicKey, killIx(PROGRAM, guardian.publicKey, vault));
  kill.sign(owner, guardian);
  const killed = await send(kill);
  if (killed.error) throw new Error(killed.error);
  console.log(`   guardian killed the vault\n   ${link(killed.signature)}`);
  const { signature, error } = await send(approved);
  if (!error) throw new Error("a killed vault paid out");
  console.log(`   the transfer the Guard approved before the kill: ${error}\n   ${link(signature)}`);
}

scene(6, "The owner takes the money back out of the killed vault");
{
  const account = await connection.getAccountInfo(vault);
  const spare = (await connection.getBalance(vault)) - (await connection.getMinimumBalanceForRentExemption(account!.data.length));
  const tx = await build(owner.publicKey, withdrawIx(PROGRAM, owner.publicKey, vault, owner.publicKey, spare));
  tx.sign(owner);
  const { signature, error } = await send(tx);
  if (error) throw new Error(error);
  console.log(`   withdrew ${(spare / SOL).toFixed(4)} SOL to the owner; the agent could not have\n   ${link(signature)}`);
}

console.log(`\nvault: https://explorer.solana.com/address/${vault.toBase58()}?cluster=devnet`);
