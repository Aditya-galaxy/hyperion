// The TypeScript client against the Python client's reference vectors
// (test/vectors.json, made by test/make_vectors.py), and its API calls
// against a stand-in for the Guard.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { Keypair, PublicKey, Transaction, TransactionInstruction } from "@solana/web3.js";
import bs58 from "bs58";
import nacl from "tweetnacl";

import {
  GuardApiError, GuardClient, GuardRefused, actionMessage, addGuardSignature, executeIx, initializeIx, killIx,
  policyMessage, reviveIx, transferSolIx, vaultAddress, withdrawIx,
} from "../src/index.ts";
import type { GuardPolicy, Verdict } from "../src/index.ts";

const V = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8"));
const K = Object.fromEntries(
  ["program", "owner", "agent", "guardian", "guard", "to"].map((name) => [name, new PublicKey(V.keys[name])]),
) as Record<"program" | "owner" | "agent" | "guardian" | "guard" | "to", PublicKey>;
const VAULT = new PublicKey(V.vault.address);

interface IxVector { programId: string; data: string; keys: { pubkey: string; isSigner: boolean; isWritable: boolean }[] }

function same(ix: TransactionInstruction, expected: IxVector): void {
  assert.equal(ix.programId.toBase58(), expected.programId);
  assert.equal(Buffer.from(ix.data).toString("hex"), expected.data);
  assert.deepEqual(ix.keys.map((k) => ({ pubkey: k.pubkey.toBase58(), isSigner: k.isSigner, isWritable: k.isWritable })), expected.keys);
}

test("the vault address is the one Python and the program derive", () => {
  const [address, bump] = vaultAddress(K.program, K.owner, K.agent);
  assert.equal(address.toBase58(), V.vault.address);
  assert.equal(bump, V.vault.bump);
  assert.equal(address.toBase58(), "7nBk9JTMcododJyarAbXMD5p5MHNr6xPJd1sWdTCeKcq");      // also pinned in the Rust tests
});

test("Initialize", () => {
  const policy = { guardian: K.guardian, guard: K.guard, maxLamportsPerTx: BigInt(V.initialize.maxLamports),
                   allowedPrograms: V.keys.allowedPrograms.map((p: string) => new PublicKey(p)) };
  same(initializeIx(K.program, K.owner, K.agent, policy), V.initialize);
  const nine = Array.from({ length: 9 }, () => Keypair.generate().publicKey);
  assert.throws(() => initializeIx(K.program, K.owner, K.agent, { ...policy, allowedPrograms: nine }), RangeError);
});

test("TransferSol, to the top of a u64", () => {
  same(transferSolIx(K.program, VAULT, K.agent, K.guard, K.to, BigInt(V.transferSol.lamports)), V.transferSol);
  same(transferSolIx(K.program, VAULT, K.agent, K.guard, K.to, 20_000_000), V.transferSol);                 // a number works too
  same(transferSolIx(K.program, VAULT, K.agent, K.guard, K.to, BigInt(V.transferSolMax.lamports)), V.transferSolMax);
  assert.throws(() => transferSolIx(K.program, VAULT, K.agent, K.guard, K.to, -1n), RangeError);
  assert.throws(() => transferSolIx(K.program, VAULT, K.agent, K.guard, K.to, 2n ** 64n), RangeError);
});

test("Execute wraps the inner call and never marks the vault as a signer", () => {
  const inner = new TransactionInstruction({
    programId: new PublicKey(V.execute.inner.programId),
    keys: V.execute.inner.keys.map((k: IxVector["keys"][number]) => ({ ...k, pubkey: new PublicKey(k.pubkey) })),
    data: Buffer.from(V.execute.inner.data, "hex"),
  });
  const outer = executeIx(K.program, VAULT, K.agent, K.guard, inner);
  same(outer, V.execute);
  assert.equal(outer.keys.find((k) => k.pubkey.equals(VAULT) && k.isSigner), undefined);
});

test("Kill, Revive and Withdraw", () => {
  same(killIx(K.program, K.guardian, VAULT), V.kill);
  same(reviveIx(K.program, K.owner, VAULT), V.revive);
  same(withdrawIx(K.program, K.owner, VAULT, K.to, BigInt(V.withdraw.lamports)), V.withdraw);
});

function fromVector(p: Record<string, any>): GuardPolicy {
  return {
    agentId: p.agent_id, agent: new PublicKey(p.agent), owner: new PublicKey(p.owner),
    guardian: p.guardian ? new PublicKey(p.guardian) : undefined,
    maxOrderNotionalUsd: p.max_order_notional_usd, maxSlippageBps: p.max_slippage_bps,
    policyVersion: p.policy_version, nonce: p.nonce, requireGuardSigner: p.require_guard_signer,
    allowedPrograms: p.allowed_programs?.map((k: string) => new PublicKey(k)),
    vaultAddress: p.vault_address ? new PublicKey(p.vault_address) : undefined,
  };
}

test("the policy message is byte for byte what Python signs", () => {
  assert.equal(V.policyMessages.length, 3);
  for (const { policy, hex } of V.policyMessages) {
    assert.equal(Buffer.from(policyMessage(fromVector(policy))).toString("hex"), hex, policy.agent_id);
  }
});

test("a dollar cap with more than two decimals is refused, not rounded", () => {
  const base = fromVector(V.policyMessages[0].policy);
  for (const bad of [0.125, 1.005, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(() => policyMessage({ ...base, maxOrderNotionalUsd: bad }), RangeError, String(bad));
  }
  assert.doesNotThrow(() => policyMessage({ ...base, maxOrderNotionalUsd: 0.1 + 0.2 }));      // 0.30000000000000004 is thirty cents
});

test("kill and revive messages", () => {
  for (const { action, agentId, nonce, hex } of V.actionMessages) {
    assert.equal(Buffer.from(actionMessage(action, agentId, nonce)).toString("hex"), hex);
  }
});

// ── the API client, against a stand-in Guard ────────────────────────────────

const guardKey = Keypair.generate();

function standIn(handler: (path: string, body: any) => { status?: number; json: unknown }) {
  const calls: { method: string; path: string; body: any }[] = [];
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const path = new URL(String(input)).pathname;
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ method: init?.method ?? "GET", path, body });
    const { status = 200, json } = handler(path, body);
    return new Response(JSON.stringify(json), { status, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  return { client: new GuardClient("https://guard.example/", { fetch: fetchImpl }), calls };
}

function agentTx(agent: Keypair): Transaction {
  const [vault] = vaultAddress(K.program, K.owner, agent.publicKey);
  const tx = new Transaction({ feePayer: agent.publicKey, recentBlockhash: bs58.encode(new Uint8Array(32).fill(8)) });
  tx.add(transferSolIx(K.program, vault, agent.publicKey, guardKey.publicKey, K.to, 20_000_000n));
  tx.partialSign(agent);
  return tx;
}

function verdictFor(body: any, approved: boolean): Verdict {
  const message = Transaction.from(Buffer.from(body.tx_bytes, "base64")).serializeMessage();
  return {
    approved, status: approved ? "APPROVED" : "REJECTED_ORDER_CAP",
    violation_details: approved ? null : "Order notional $6.00 exceeds cap of $5.00", agent_id: body.agent_id,
    recent_blockhash: "", decoded_operations: ["Hyperion Guarded Vault::VAULT_TRANSFER_SOL"],
    cosigner_pubkey: guardKey.publicKey.toBase58(),
    cosigner_signature_b58: approved ? bs58.encode(nacl.sign.detached(message, guardKey.secretKey)) : null,
  };
}

test("an approved transaction comes back fully signed and valid", async () => {
  const agent = Keypair.generate();
  const { client, calls } = standIn((path, body) => ({ json: verdictFor(body, true) }));
  const tx = agentTx(agent);
  assert.equal(tx.verifySignatures(true), false);                    // the Guard's slot is empty
  const sent = await client.checkAndCosign("agent-1", tx);
  assert.equal(sent, tx);
  assert.equal(tx.verifySignatures(true), true);                     // both signatures, both valid
  assert.equal(tx.signatures.length, 2);
  assert.deepEqual(calls.map((c) => [c.method, c.path, c.body.agent_id, c.body.encoding]), [["POST", "/v1/solana/check", "agent-1", "base64"]]);
});

test("a refusal throws, and leaves the transaction unsigned by the Guard", async () => {
  const { client } = standIn((path, body) => ({ json: verdictFor(body, false) }));
  const tx = agentTx(Keypair.generate());
  await assert.rejects(client.checkAndCosign("agent-1", tx), (e: unknown) => {
    assert.ok(e instanceof GuardRefused);
    assert.equal(e.verdict.status, "REJECTED_ORDER_CAP");
    assert.match(e.message, /exceeds cap/);
    return true;
  });
  assert.equal(tx.verifySignatures(true), false);
  assert.throws(() => addGuardSignature(tx, verdictFor({ tx_bytes: tx.serialize({ requireAllSignatures: false }).toString("base64"), agent_id: "a" }, false)), GuardRefused);
});

test("setting a policy sends every field and the owner's signature over the message", async () => {
  const owner = Keypair.generate();
  const policy: GuardPolicy = { ...fromVector(V.policyMessages[1].policy), owner: owner.publicKey };
  const { client, calls } = standIn(() => ({ json: { ok: true } }));
  await client.setPolicy(policy, (message) => nacl.sign.detached(message, owner.secretKey));
  const body = calls[0]!.body;
  assert.equal(calls[0]!.path, "/v1/solana/policy");
  assert.ok(nacl.sign.detached.verify(policyMessage(policy), bs58.decode(body.signature_b58), owner.publicKey.toBytes()));
  assert.deepEqual(
    [body.agent_id, body.agent_solana_pubkey, body.owner_solana_pubkey, body.guardian_solana_pubkey, body.max_order_notional_usd,
     body.max_slippage_bps, body.require_guard_signer, body.vault_address, body.allowed_programs.length],
    ["desk/agent 2", V.keys.agent, owner.publicKey.toBase58(), V.keys.guardian, 3.96, 25, false, V.vault.address, 3]);
});

test("kill and revive are signed by the caller", async () => {
  const owner = Keypair.generate();
  const sign = (message: Uint8Array) => nacl.sign.detached(message, owner.secretKey);
  const { client, calls } = standIn(() => ({ json: { ok: true } }));
  await client.kill("agent-1", owner.publicKey, 5, sign, "looks wrong");
  await client.revive("agent-1", owner.publicKey, 6, sign);
  assert.deepEqual(calls.map((c) => [c.path, c.body.nonce, c.body.caller_pubkey]),
                   [["/v1/solana/kill", 5, owner.publicKey.toBase58()], ["/v1/solana/revive", 6, owner.publicKey.toBase58()]]);
  assert.ok(nacl.sign.detached.verify(actionMessage("kill", "agent-1", 5), bs58.decode(calls[0]!.body.signature_b58), owner.publicKey.toBytes()));
  assert.ok(nacl.sign.detached.verify(actionMessage("revive", "agent-1", 6), bs58.decode(calls[1]!.body.signature_b58), owner.publicKey.toBytes()));
});

test("an API error carries its status and the Guard's reason", async () => {
  const { client } = standIn(() => ({ status: 429, json: { detail: "Too many writes from this address. Try again in 12 s." } }));
  await assert.rejects(client.check("agent-1", new Uint8Array([1, 2, 3])), (e: unknown) => {
    assert.ok(e instanceof GuardApiError);
    assert.equal(e.status, 429);
    assert.match(e.detail, /Too many writes/);
    return true;
  });
});

test("the co-signing key is fetched once", async () => {
  const { client, calls } = standIn(() => ({ json: { ok: true, cosigner_pubkey: guardKey.publicKey.toBase58() } }));
  assert.ok((await client.cosignerKey()).equals(guardKey.publicKey));
  assert.ok((await client.cosignerKey()).equals(guardKey.publicKey));
  assert.equal(calls.length, 1);
  assert.equal(client.url, "https://guard.example");
});
