/**
 * Hyperion Guard, from TypeScript.
 *
 * Two halves, as in the Python client (guard/service/hyperion_guard/solana):
 *
 *   - instructions for the Guarded Vault program (guard/contracts_solana),
 *     byte for byte the encoding its README gives;
 *   - a client for the Guard's HTTP API: set a policy, ask about a
 *     transaction, attach the co-signature that comes back.
 *
 * An agent's transaction is a vault instruction with the Guard as a required
 * signer. The agent signs, asks the Guard, and sends only if it co-signs:
 *
 *     const ix = transferSolIx(program, vault, agent.publicKey, guardKey, merchant, 20_000_000n);
 *     const tx = new Transaction({ feePayer: agent.publicKey, recentBlockhash }).add(ix);
 *     tx.partialSign(agent);
 *     await guard.checkAndCosign("agent-1", tx);      // throws GuardRefused if the Guard says no
 *     await connection.sendRawTransaction(tx.serialize());
 *
 * The vector tests in test/ check this file against the Python client.
 */

import { PublicKey, SystemProgram, Transaction, TransactionInstruction, VersionedTransaction } from "@solana/web3.js";
import bs58 from "bs58";

export const VAULT_SEED = "hyperion-vault";
export const MAX_PROGRAMS = 8;

const TAG = { initialize: 0, transferSol: 1, execute: 2, kill: 3, revive: 4, withdraw: 6 } as const;
const encoder = new TextEncoder();

function u64(value: bigint | number): Uint8Array {
  const v = BigInt(value);
  if (v < 0n || v > 0xffff_ffff_ffff_ffffn) throw new RangeError(`${value} doesn't fit in a u64`);
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, v, true);
  return out;
}

function concat(...parts: Uint8Array[]): Buffer {
  return Buffer.concat(parts.map((p) => Buffer.from(p)));
}

// ── the vault ───────────────────────────────────────────────────────────────

/** The vault's address for an owner and an agent, and its bump. */
export function vaultAddress(programId: PublicKey, owner: PublicKey, agent: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([encoder.encode(VAULT_SEED), owner.toBytes(), agent.toBytes()], programId);
}

export interface VaultPolicy {
  /** May kill the vault. */
  guardian: PublicKey;
  /** The Guard's co-signing key: every agent action needs its signature. */
  guard: PublicKey;
  /** The most SOL an agent action may move, in lamports. */
  maxLamportsPerTx: bigint | number;
  /** Programs the vault may call through Execute. At most eight. */
  allowedPrograms?: PublicKey[];
}

/** The owner opens a vault for an agent. Signed by the owner, who pays its rent. */
export function initializeIx(programId: PublicKey, owner: PublicKey, agent: PublicKey, policy: VaultPolicy): TransactionInstruction {
  const programs = policy.allowedPrograms ?? [];
  if (programs.length > MAX_PROGRAMS) throw new RangeError(`at most ${MAX_PROGRAMS} allowed programs`);
  const [vault] = vaultAddress(programId, owner, agent);
  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: owner, isSigner: true, isWritable: true },
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: concat(
      Uint8Array.of(TAG.initialize), policy.guardian.toBytes(), agent.toBytes(), policy.guard.toBytes(),
      u64(policy.maxLamportsPerTx), Uint8Array.of(programs.length), ...programs.map((p) => p.toBytes()),
    ),
  });
}

/** The agent pays SOL out of its vault. Needs the agent's and the Guard's signatures. */
export function transferSolIx(
  programId: PublicKey, vault: PublicKey, agent: PublicKey, guard: PublicKey, to: PublicKey, lamports: bigint | number,
): TransactionInstruction {
  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: agent, isSigner: true, isWritable: false },
      { pubkey: guard, isSigner: true, isWritable: false },
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: to, isSigner: false, isWritable: true },
    ],
    data: concat(Uint8Array.of(TAG.transferSol), u64(lamports)),
  });
}

/**
 * Wrap `inner` so the vault makes the call, signing as itself: a Jupiter swap
 * or a token transfer spending the vault's own accounts. Wherever `inner`
 * names the vault as a signer, the outer instruction doesn't: the program
 * signs for it.
 */
export function executeIx(
  programId: PublicKey, vault: PublicKey, agent: PublicKey, guard: PublicKey, inner: TransactionInstruction,
): TransactionInstruction {
  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: agent, isSigner: true, isWritable: false },
      { pubkey: guard, isSigner: true, isWritable: false },
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: inner.programId, isSigner: false, isWritable: false },
      ...inner.keys.map((k) => ({ pubkey: k.pubkey, isSigner: k.isSigner && !k.pubkey.equals(vault), isWritable: k.isWritable })),
    ],
    data: concat(Uint8Array.of(TAG.execute), inner.data),
  });
}

function callerIx(tag: number, programId: PublicKey, caller: PublicKey, vault: PublicKey): TransactionInstruction {
  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: caller, isSigner: true, isWritable: false },
      { pubkey: vault, isSigner: false, isWritable: true },
    ],
    data: Buffer.from([tag]),
  });
}

/** The owner or the guardian stops the vault. */
export function killIx(programId: PublicKey, caller: PublicKey, vault: PublicKey): TransactionInstruction {
  return callerIx(TAG.kill, programId, caller, vault);
}

/** The owner, and only the owner, brings the vault back. */
export function reviveIx(programId: PublicKey, owner: PublicKey, vault: PublicKey): TransactionInstruction {
  return callerIx(TAG.revive, programId, owner, vault);
}

/** The owner takes SOL out of the vault, killed or not. */
export function withdrawIx(programId: PublicKey, owner: PublicKey, vault: PublicKey, to: PublicKey, lamports: bigint | number): TransactionInstruction {
  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: owner, isSigner: true, isWritable: false },
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: to, isSigner: false, isWritable: true },
    ],
    data: concat(Uint8Array.of(TAG.withdraw), u64(lamports)),
  });
}

// ── what an owner or guardian signs ─────────────────────────────────────────

export interface GuardPolicy {
  agentId: string;
  /** The agent's own key. The Guard judges only transactions it has signed. */
  agent: PublicKey;
  owner: PublicKey;
  guardian?: PublicKey;
  /** Dollars, with at most two decimal places. */
  maxOrderNotionalUsd: number;
  maxSlippageBps: number;
  /** Must go up with every update. */
  policyVersion: number;
  /** Must be above every nonce this agent's owner or guardian has used. */
  nonce: number;
  requireGuardSigner?: boolean;
  /** Programs the agent may call. Omit for the Guard's built-in list. */
  allowedPrograms?: PublicKey[];
  /** If set, vault instructions must use this vault. */
  vaultAddress?: PublicKey;
}

/** JSON as Python's json.dumps writes it by default: non-ASCII as \uXXXX. */
function pythonJson(value: unknown): string {
  return JSON.stringify(value).replace(/[\u007f-￿]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
}

function dollars(value: number): string {
  // Two decimals exactly, so there is no rounding for two languages to disagree about.
  const cents = Math.round(value * 100);
  if (!Number.isFinite(value) || value < 0 || Math.abs(value * 100 - cents) > 1e-6) {
    throw new RangeError(`maxOrderNotionalUsd must be dollars with at most two decimals, got ${value}`);
  }
  return (cents / 100).toFixed(2);
}

/** The bytes an owner signs to set a policy: every field of it, in a fixed order. */
export function policyMessage(p: GuardPolicy): Uint8Array {
  const programs = p.allowedPrograms?.length ? p.allowedPrograms.map((k) => k.toBase58()).sort() : null;
  // keys in sorted order, no spaces: what json.dumps(sort_keys=True, separators=(",", ":")) writes
  const fields: [string, unknown][] = [
    ["agent", p.agent.toBase58()],
    ["agent_id", p.agentId],
    ["allowed_programs", programs],
    ["guardian", p.guardian?.toBase58() ?? ""],
    ["max_order_notional_usd", dollars(p.maxOrderNotionalUsd)],
    ["max_slippage_bps", Math.trunc(p.maxSlippageBps)],
    ["nonce", Math.trunc(p.nonce)],
    ["owner", p.owner.toBase58()],
    ["policy_version", Math.trunc(p.policyVersion)],
    ["require_guard_signer", p.requireGuardSigner ?? true],
    ["vault_address", p.vaultAddress?.toBase58() ?? ""],
  ];
  const json = "{" + fields.map(([k, v]) => `${pythonJson(k)}:${pythonJson(v)}`).join(",") + "}";
  return encoder.encode("hyperion-guard/solana/policy/v3:" + json);
}

/** The bytes an owner or guardian signs to kill an agent at the Guard, or an owner to revive it. */
export function actionMessage(action: "kill" | "revive", agentId: string, nonce: number): Uint8Array {
  return encoder.encode(`hyperion-guard/solana/${action}/v1:${agentId}:${Math.trunc(nonce)}`);
}

// ── the Guard's API ─────────────────────────────────────────────────────────

export interface Verdict {
  approved: boolean;
  /** "APPROVED", or why not: "REJECTED_ORDER_CAP", "REJECTED_KILL_SWITCH", ... */
  status: string;
  violation_details: string | null;
  agent_id: string;
  recent_blockhash: string;
  decoded_operations: string[];
  cosigner_pubkey: string;
  /** The Guard's signature over the transaction's message, base58. Null unless approved. */
  cosigner_signature_b58: string | null;
}

/** The Guard looked at the transaction and would not sign it. */
export class GuardRefused extends Error {
  readonly verdict: Verdict;
  constructor(verdict: Verdict) {
    super(`${verdict.status}: ${verdict.violation_details ?? "refused"}`);
    this.name = "GuardRefused";
    this.verdict = verdict;
  }
}

/** The Guard's API answered with an error (a bad request, a rate limit, an outage). */
export class GuardApiError extends Error {
  readonly status: number;
  readonly detail: string;
  constructor(status: number, detail: string) {
    super(`Guard API ${status}: ${detail}`);
    this.name = "GuardApiError";
    this.status = status;
    this.detail = detail;
  }
}

/** Signs a message with an Ed25519 key and returns the 64-byte signature. */
export type Signer = (message: Uint8Array) => Uint8Array | Promise<Uint8Array>;

type AnyTransaction = Transaction | VersionedTransaction;

function wireBytes(tx: AnyTransaction | Uint8Array): Uint8Array {
  if (tx instanceof Uint8Array) return tx;
  if (tx instanceof VersionedTransaction) return tx.serialize();
  // the Guard's slot is still empty, so don't insist on every signature
  return tx.serialize({ requireAllSignatures: false, verifySignatures: false });
}

export class GuardClient {
  readonly url: string;
  private readonly fetchImpl: typeof fetch;
  private cosigner?: PublicKey;

  constructor(url: string, options: { fetch?: typeof fetch } = {}) {
    this.url = url.replace(/\/+$/, "");
    this.fetchImpl = options.fetch ?? fetch;
  }

  private async call<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<T> {
    const res = await this.fetchImpl(this.url + path, {
      method,
      headers: body === undefined ? {} : { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    let parsed: unknown;
    try {
      parsed = text ? JSON.parse(text) : {};
    } catch {
      parsed = { detail: text };
    }
    if (!res.ok) {
      const detail = (parsed as { detail?: unknown }).detail;
      throw new GuardApiError(res.status, typeof detail === "string" ? detail : JSON.stringify(detail ?? parsed));
    }
    return parsed as T;
  }

  /** The Guard's co-signing key: name it as a required signer in the agent's transactions. */
  async cosignerKey(): Promise<PublicKey> {
    if (!this.cosigner) {
      const health = await this.call<{ cosigner_pubkey: string }>("GET", "/v1/solana/health");
      this.cosigner = new PublicKey(health.cosigner_pubkey);
    }
    return this.cosigner;
  }

  /** Set or update an agent's policy. `sign` signs with the owner's key. */
  async setPolicy(policy: GuardPolicy, sign: Signer): Promise<void> {
    const signature = await sign(policyMessage(policy));
    await this.call("POST", "/v1/solana/policy", {
      agent_id: policy.agentId,
      agent_solana_pubkey: policy.agent.toBase58(),
      owner_solana_pubkey: policy.owner.toBase58(),
      guardian_solana_pubkey: policy.guardian?.toBase58() ?? "",
      max_order_notional_usd: Number(dollars(policy.maxOrderNotionalUsd)),
      max_slippage_bps: Math.trunc(policy.maxSlippageBps),
      policy_version: Math.trunc(policy.policyVersion),
      nonce: Math.trunc(policy.nonce),
      require_guard_signer: policy.requireGuardSigner ?? true,
      ...(policy.allowedPrograms?.length ? { allowed_programs: policy.allowedPrograms.map((k) => k.toBase58()) } : {}),
      vault_address: policy.vaultAddress?.toBase58() ?? "",
      signature_b58: bs58.encode(signature),
    });
  }

  /** Stop an agent at the Guard. `sign` signs with the owner's or the guardian's key. */
  async kill(agentId: string, caller: PublicKey, nonce: number, sign: Signer, reason = ""): Promise<void> {
    const signature = await sign(actionMessage("kill", agentId, nonce));
    await this.call("POST", "/v1/solana/kill", {
      agent_id: agentId, caller_pubkey: caller.toBase58(), nonce, signature_b58: bs58.encode(signature), reason,
    });
  }

  /** Bring an agent back at the Guard. `sign` signs with the owner's key. */
  async revive(agentId: string, owner: PublicKey, nonce: number, sign: Signer): Promise<void> {
    const signature = await sign(actionMessage("revive", agentId, nonce));
    await this.call("POST", "/v1/solana/revive", {
      agent_id: agentId, caller_pubkey: owner.toBase58(), nonce, signature_b58: bs58.encode(signature),
    });
  }

  /**
   * Ask the Guard about a transaction the agent has already signed. The
   * verdict says whether it approved, and carries its co-signature if so.
   */
  async check(agentId: string, tx: AnyTransaction | Uint8Array): Promise<Verdict> {
    return this.call<Verdict>("POST", "/v1/solana/check", {
      agent_id: agentId, tx_bytes: Buffer.from(wireBytes(tx)).toString("base64"), encoding: "base64",
    });
  }

  /**
   * Ask the Guard, and put its signature on the transaction if it approves.
   * Throws GuardRefused if it doesn't. The transaction is changed in place
   * and returned, ready to send.
   */
  async checkAndCosign<T extends AnyTransaction>(agentId: string, tx: T): Promise<T> {
    const verdict = await this.check(agentId, tx);
    if (!verdict.approved || !verdict.cosigner_signature_b58) throw new GuardRefused(verdict);
    addGuardSignature(tx, verdict);
    return tx;
  }
}

/** Put an approving verdict's co-signature into the Guard's slot of the transaction. */
export function addGuardSignature(tx: AnyTransaction, verdict: Verdict): void {
  if (!verdict.approved || !verdict.cosigner_signature_b58) throw new GuardRefused(verdict);
  const guard = new PublicKey(verdict.cosigner_pubkey);
  const signature = bs58.decode(verdict.cosigner_signature_b58);
  if (tx instanceof VersionedTransaction) tx.addSignature(guard, signature);
  else tx.addSignature(guard, Buffer.from(signature));
}
