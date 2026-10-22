// The Solana Agent Kit plugin, in a real SolanaAgentKit, against a stand-in
// for the Guard and a stand-in for the RPC node: it should send only what the
// Guard co-signed, and tell an LLM why when the Guard refuses.

import assert from "node:assert/strict";
import { test } from "node:test";

import { Keypair, LAMPORTS_PER_SOL, PublicKey, SystemProgram, Transaction } from "@solana/web3.js";
import type { Connection } from "@solana/web3.js";
import bs58 from "bs58";
import { KeypairWallet, SolanaAgentKit, createVercelAITools, executeAction } from "solana-agent-kit";
import nacl from "tweetnacl";

import { HyperionGuardPlugin } from "../src/agent-kit.ts";
import { GuardRefused, MAX_PROGRAMS, decodeVault, vaultAddress } from "../src/index.ts";

const PROGRAM = new PublicKey("9btLSADcT2u3M1HnC4cdkV4HiN662bqmhHYvevaSragq");
const guardKey = Keypair.generate();
const owner = Keypair.generate().publicKey;
const merchant = Keypair.generate().publicKey;
const BLOCKHASH = bs58.encode(new Uint8Array(32).fill(8));

/** A Guard that approves up to `capLamports` a transaction. */
function standInGuard(capLamports: bigint) {
  const checked: Transaction[] = [];
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const path = new URL(String(input)).pathname;
    const json = (body: unknown) => new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } });
    if (path === "/v1/solana/health") return json({ cosigner_pubkey: guardKey.publicKey.toBase58() });
    const body = JSON.parse(String(init!.body));
    const tx = Transaction.from(Buffer.from(body.tx_bytes, "base64"));
    checked.push(tx);
    const data = tx.instructions[0]!.data;
    const lamports = data[0] === 1 ? data.readBigUInt64LE(1) : 0n;
    const approved = lamports <= capLamports;
    return json({
      approved, status: approved ? "APPROVED" : "REJECTED_ORDER_CAP",
      violation_details: approved ? null : "Order notional $8.00 exceeds cap of $5.00", agent_id: body.agent_id,
      recent_blockhash: BLOCKHASH, decoded_operations: ["Hyperion Guarded Vault::VAULT_TRANSFER_SOL"],
      cosigner_pubkey: guardKey.publicKey.toBase58(),
      cosigner_signature_b58: approved ? bs58.encode(nacl.sign.detached(tx.serializeMessage(), guardKey.secretKey)) : null,
    });
  }) as typeof fetch;
  return { fetchImpl, checked };
}

/** Vault account bytes, laid out as guard/contracts_solana/src/state.rs packs them. */
function vaultBytes(agent: PublicKey, killed: boolean, maxLamports: bigint): Buffer {
  const b = Buffer.alloc(148 + 32 * MAX_PROGRAMS);
  b[0] = 1;
  b[1] = killed ? 1 : 0;
  b[2] = 254;
  owner.toBuffer().copy(b, 3);
  agent.toBuffer().copy(b, 67);                                       // no guardian: bytes 35..67 stay zero
  guardKey.publicKey.toBuffer().copy(b, 99);
  b.writeBigUInt64LE(maxLamports, 131);
  b.writeBigUInt64LE(3n, 139);
  b[147] = 1;
  SystemProgram.programId.toBuffer().copy(b, 148);
  return b;
}

/** An agent kit whose RPC is a stand-in that records what it's asked to send. */
function makeAgent(capLamports = 50_000_000n) {
  const agentKey = Keypair.generate();
  const guard = standInGuard(capLamports);
  const sent: Transaction[] = [];
  const [vault] = vaultAddress(PROGRAM, owner, agentKey.publicKey);
  const agent = new SolanaAgentKit(new KeypairWallet(agentKey, "http://rpc.invalid"), "http://rpc.invalid", {})
    .use(HyperionGuardPlugin({ guardUrl: "https://guard.example", programId: PROGRAM, owner, agentId: "agent-1", fetch: guard.fetchImpl }));
  agent.connection = {
    getLatestBlockhash: async () => ({ blockhash: BLOCKHASH, lastValidBlockHeight: 100 }),
    sendRawTransaction: async (raw: Buffer) => {
      const tx = Transaction.from(raw);
      sent.push(tx);
      return bs58.encode(tx.signature!);
    },
    confirmTransaction: async () => ({ context: { slot: 1 }, value: { err: null } }),
    getAccountInfo: async (address: PublicKey) =>
      address.equals(vault) ? { data: vaultBytes(agentKey.publicKey, false, 50_000_000n), lamports: 0.1 * LAMPORTS_PER_SOL } : null,
  } as unknown as Connection;
  return { agent, agentKey, vault, sent, checked: guard.checked };
}

const action = (agent: SolanaAgentKit, name: string) => agent.actions.find((a) => a.name === name)!;

test("an approved payment is signed by the agent, co-signed by the Guard, and sent", async () => {
  const { agent, agentKey, vault, sent, checked } = makeAgent();
  const result = await agent.methods.guardedTransferSol(agent, merchant, 0.02);
  assert.equal(sent.length, 1);
  const tx = sent[0]!;
  assert.equal(tx.verifySignatures(true), true);                     // both signatures, both valid
  assert.deepEqual(tx.signatures.map((s) => s.publicKey.toBase58()).sort(), [agentKey.publicKey, guardKey.publicKey].map((k) => k.toBase58()).sort());
  const ix = tx.instructions[0]!;
  assert.ok(ix.programId.equals(PROGRAM));
  assert.deepEqual(ix.keys.map((k) => k.pubkey.toBase58()), [agentKey.publicKey, guardKey.publicKey, vault, merchant].map((k) => k.toBase58()));
  assert.equal(ix.data.readBigUInt64LE(1), 20_000_000n);
  assert.equal(result.signature, bs58.encode(tx.signature!));
  assert.equal(checked[0]!.signatures.find((s) => s.publicKey.equals(agentKey.publicKey))!.signature !== null, true);  // the Guard saw the agent's signature
});

test("a refused payment throws, and nothing is sent", async () => {
  const { agent, sent } = makeAgent();
  await assert.rejects(agent.methods.guardedTransferSol(agent, merchant, 0.08), (e: unknown) => {
    assert.ok(e instanceof GuardRefused);
    assert.equal(e.verdict.status, "REJECTED_ORDER_CAP");
    return true;
  });
  assert.equal(sent.length, 0);
});

test("an LLM is told the Guard's reason, not an error", async () => {
  const { agent, sent } = makeAgent();
  const pay = action(agent, "HYPERION_GUARDED_TRANSFER_SOL");
  const refused = await executeAction(pay, agent, { to: merchant.toBase58(), amountSol: 0.08 });
  assert.deepEqual(refused, { status: "refused", guardStatus: "REJECTED_ORDER_CAP", reason: "Order notional $8.00 exceeds cap of $5.00", sent: false });
  const paid = await executeAction(pay, agent, { to: merchant.toBase58(), amountSol: 0.02 });
  assert.equal(paid.status, "success");
  assert.equal(paid.sent, true);
  assert.equal(sent.length, 1);
  const invalid = await executeAction(pay, agent, { to: merchant.toBase58(), amountSol: -1 });
  assert.equal(invalid.code, "VALIDATION_ERROR");
});

test("guardedExecute wraps each call so the vault makes it", async () => {
  const { agent, vault, sent } = makeAgent();
  const inner = SystemProgram.transfer({ fromPubkey: vault, toPubkey: merchant, lamports: 1 });
  await agent.methods.guardedExecute(agent, [inner]);
  const ix = sent[0]!.instructions[0]!;
  assert.ok(ix.programId.equals(PROGRAM));
  assert.equal(ix.data[0], 2);                                        // Execute
  assert.ok(ix.keys[3]!.pubkey.equals(SystemProgram.programId));
  assert.equal(ix.keys.find((k) => k.pubkey.equals(vault))!.isSigner, false);   // the program signs for the vault
});

test("vault info reads the account", async () => {
  const { agent, vault } = makeAgent();
  const info = await executeAction(action(agent, "HYPERION_GUARD_VAULT_INFO"), agent, {});
  assert.deepEqual(info, {
    status: "success", vault: vault.toBase58(), balanceSol: 0.1, killed: false, maxSolPerTx: 0.05, executions: 3,
    guard: guardKey.publicKey.toBase58(), agentId: "agent-1",
  });
});

test("decodeVault", () => {
  const agent = Keypair.generate().publicKey;
  const v = decodeVault(vaultBytes(agent, true, 7n))!;
  assert.equal(v.killed, true);
  assert.equal(v.guardian, null);
  assert.ok(v.owner.equals(owner) && v.agent.equals(agent) && v.guard.equals(guardKey.publicKey));
  assert.equal(v.maxLamportsPerTx, 7n);
  assert.deepEqual(v.allowedPrograms.map((p) => p.toBase58()), [SystemProgram.programId.toBase58()]);
  assert.equal(decodeVault(Buffer.alloc(404)), null);                 // not initialized
  assert.equal(decodeVault(Buffer.alloc(10, 1)), null);               // too short
});

test("the kit turns the actions into LLM tools", () => {
  const { agent } = makeAgent();
  const tools = createVercelAITools(agent, agent.actions);
  const ids = Object.values(tools).map((t) => (t as { id?: string }).id);       // keyed by index, named by id
  assert.deepEqual(ids, ["HYPERION_GUARDED_TRANSFER_SOL", "HYPERION_GUARD_VAULT_INFO"]);
});
