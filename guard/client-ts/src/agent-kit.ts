/**
 * The Hyperion Guard as a Solana Agent Kit plugin.
 *
 * The kit's wallet is the agent's own key, holding only enough SOL for fees.
 * The agent's working money is in a Guarded Vault, which pays only when the
 * Guard co-signs. This plugin gives the agent ways to spend from the vault:
 * it builds the vault instruction, signs with the kit's wallet, asks the
 * Guard, and sends only if the Guard co-signs.
 *
 *     import { SolanaAgentKit, KeypairWallet, createVercelAITools } from "solana-agent-kit";
 *     import { HyperionGuardPlugin } from "hyperion-guard-client/agent-kit";
 *
 *     const agent = new SolanaAgentKit(new KeypairWallet(agentKey, rpc), rpc, {})
 *       .use(HyperionGuardPlugin({ guardUrl, programId, owner, agentId: "agent-1" }));
 *     await agent.methods.guardedTransferSol(agent, merchant, 0.02);   // throws GuardRefused if the Guard says no
 *     const tools = createVercelAITools(agent, agent.actions);         // or hand the actions to an LLM
 *
 * Nothing here imports the kit at runtime, only its types: the plugin works
 * with whichever copy of solana-agent-kit the agent uses.
 */

import { LAMPORTS_PER_SOL, PublicKey, Transaction } from "@solana/web3.js";
import type { TransactionInstruction } from "@solana/web3.js";
import type { Action, Plugin, SolanaAgentKit } from "solana-agent-kit";
import { z } from "zod";

import { GuardClient, GuardRefused, addGuardSignature, decodeVault, executeIx, transferSolIx, vaultAddress } from "./index.ts";
import type { VaultState } from "./index.ts";

export interface HyperionGuardOptions {
  /** The Guard's API, e.g. https://hyperion-guard-dijsyl2kwq-uc.a.run.app */
  guardUrl: string;
  /** The Guarded Vault program. */
  programId: PublicKey | string;
  /** The vault's owner: with the kit's wallet as the agent, this fixes the vault. */
  owner: PublicKey | string;
  /** The agent's id at the Guard, as its owner registered it. */
  agentId: string;
  /** For tests: the fetch the Guard client uses. */
  fetch?: typeof fetch;
}

export interface GuardedSend {
  signature: string;
  /** What the Guard saw in the transaction. */
  operations: string[];
}

export interface VaultInfo extends VaultState {
  address: PublicKey;
  /** What the vault holds, in SOL, rent included. */
  balanceSol: number;
}

function toLamports(sol: number): bigint {
  if (!Number.isFinite(sol) || sol <= 0) throw new RangeError(`an amount of SOL must be above zero, got ${sol}`);
  return BigInt(Math.round(sol * LAMPORTS_PER_SOL));
}

/** The plugin. Each call makes one, bound to one agent's vault. */
export function HyperionGuardPlugin(options: HyperionGuardOptions) {
  const programId = new PublicKey(options.programId);
  const owner = new PublicKey(options.owner);
  const guard = new GuardClient(options.guardUrl, { fetch: options.fetch });
  const vaultOf = (agent: SolanaAgentKit) => vaultAddress(programId, owner, agent.wallet.publicKey)[0];

  /** Sign with the agent's wallet, have the Guard co-sign, send, and wait for confirmation. */
  async function guardedSend(agent: SolanaAgentKit, instructions: TransactionInstruction[]): Promise<GuardedSend> {
    const { connection, wallet } = agent;
    const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash();
    const unsigned = new Transaction({ feePayer: wallet.publicKey, recentBlockhash: blockhash }).add(...instructions);
    const tx = await wallet.signTransaction(unsigned);               // the Guard judges only what the agent signed
    const verdict = await guard.check(options.agentId, tx);
    addGuardSignature(tx, verdict);                                  // throws GuardRefused if it didn't approve
    const signature = await connection.sendRawTransaction(tx.serialize());
    const { value } = await connection.confirmTransaction({ signature, blockhash, lastValidBlockHeight }, "confirmed");
    if (value.err) throw new Error(`${signature} failed on-chain: ${JSON.stringify(value.err)}`);
    return { signature, operations: verdict.decoded_operations };
  }

  const methods = {
    /** The vault's address, balance and on-chain limits. */
    async guardVaultInfo(agent: SolanaAgentKit): Promise<VaultInfo> {
      const address = vaultOf(agent);
      const account = await agent.connection.getAccountInfo(address);
      const state = account && decodeVault(account.data);
      if (!state) throw new Error(`no Guarded Vault at ${address.toBase58()} for this owner and agent`);
      return { address, balanceSol: account.lamports / LAMPORTS_PER_SOL, ...state };
    },

    /** Pay SOL out of the vault. Throws GuardRefused if the Guard won't co-sign. */
    async guardedTransferSol(agent: SolanaAgentKit, to: PublicKey | string, amountSol: number): Promise<GuardedSend> {
      const ix = transferSolIx(programId, vaultOf(agent), agent.wallet.publicKey, await guard.cosignerKey(), new PublicKey(to), toLamports(amountSol));
      return guardedSend(agent, [ix]);
    },

    /**
     * Have the vault make calls, signing as itself: a swap or a token transfer
     * from the vault's own accounts. Each instruction is wrapped in an Execute;
     * the Guard judges the inner calls.
     */
    async guardedExecute(agent: SolanaAgentKit, instructions: TransactionInstruction[]): Promise<GuardedSend> {
      const guardKey = await guard.cosignerKey();
      const vault = vaultOf(agent);
      return guardedSend(agent, instructions.map((inner) => executeIx(programId, vault, agent.wallet.publicKey, guardKey, inner)));
    },
  };

  // What an LLM sees. A refusal is an answer, not an error: the model is told
  // the Guard's reason so it can change its plan, and nothing was sent.
  const refusal = (e: unknown) => {
    if (!(e instanceof GuardRefused)) throw e;
    return { status: "refused", guardStatus: e.verdict.status, reason: e.verdict.violation_details ?? "the Guard refused", sent: false };
  };

  const actions: Action[] = [
    {
      name: "HYPERION_GUARDED_TRANSFER_SOL",
      similes: ["pay from the vault", "send sol from the guarded vault", "pay a merchant", "transfer sol with guard approval"],
      description:
        "Pay SOL from the agent's Guarded Vault, where its working money is. The Hyperion Guard checks the payment " +
        "against the owner's policy (a dollar cap per order, a kill switch) and co-signs only if it passes. " +
        "If the Guard refuses, nothing is sent and the reason is returned; do not try to pay another way.",
      examples: [[{
        input: { to: "8x2dR8Mpzuz2YqyZyZjUbYWKSWesBo5jMx2Q9Y86udVk", amountSol: 0.02 },
        output: { status: "success", signature: "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW", sent: true },
        explanation: "Pay 0.02 SOL from the vault; the Guard approved and co-signed",
      }, {
        input: { to: "8x2dR8Mpzuz2YqyZyZjUbYWKSWesBo5jMx2Q9Y86udVk", amountSol: 5 },
        output: { status: "refused", guardStatus: "REJECTED_ORDER_CAP", reason: "Order notional $900.00 exceeds cap of $5.00", sent: false },
        explanation: "A payment over the owner's cap: the Guard won't sign, so nothing moves",
      }]],
      schema: z.object({
        to: z.string().describe("The recipient's Solana address"),
        amountSol: z.number().positive().describe("How much SOL to pay"),
      }),
      handler: async (agent, input) => {
        try {
          const { signature, operations } = await methods.guardedTransferSol(agent, input.to, input.amountSol);
          return { signature, operations, sent: true };
        } catch (e) {
          return refusal(e);
        }
      },
    },
    {
      name: "HYPERION_GUARD_VAULT_INFO",
      similes: ["vault balance", "how much can I spend", "is my vault killed", "guarded vault status"],
      description:
        "The agent's Guarded Vault: its address, its SOL balance, whether its guardian has killed it, and the most " +
        "SOL one payment may move. Check this before paying.",
      examples: [[{
        input: {},
        output: { status: "success", vault: "7nBk9JTMcododJyarAbXMD5p5MHNr6xPJd1sWdTCeKcq", balanceSol: 0.1, killed: false, maxSolPerTx: 0.05 },
        explanation: "The vault holds 0.1 SOL, is live, and pays at most 0.05 SOL a transaction",
      }]],
      schema: z.object({}),
      handler: async (agent) => {
        const v = await methods.guardVaultInfo(agent);
        return {
          vault: v.address.toBase58(), balanceSol: v.balanceSol, killed: v.killed,
          maxSolPerTx: Number(v.maxLamportsPerTx) / LAMPORTS_PER_SOL, executions: Number(v.executions),
          guard: v.guard.toBase58(), agentId: options.agentId,
        };
      },
    },
  ];

  return {
    name: "hyperion-guard",
    methods,
    actions,
    initialize() {},
  } satisfies Plugin;
}
