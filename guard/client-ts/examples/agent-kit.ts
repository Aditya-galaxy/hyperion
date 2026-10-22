// A Solana Agent Kit agent whose money is in a Guarded Vault, on devnet,
// against a hosted Guard. The agent pays through the plugin's LLM actions,
// the same calls a model would make; every transaction is real.
//
//   node examples/agent-kit.ts
//
//   [HYPERION_GUARD_URL=https://hyperion-guard-dijsyl2kwq-uc.a.run.app]
//   [SOLANA_RPC_URL=https://api.devnet.solana.com]
//   [SOLANA_KEYPAIR=~/.config/solana/id.json]      the owner; pays about 0.01 SOL a run
//   [HYPERION_VAULT_PROGRAM_ID=9btLSADcT2u3M1HnC4cdkV4HiN662bqmhHYvevaSragq]

import { readFileSync } from "node:fs";
import { homedir } from "node:os";

import { Keypair, LAMPORTS_PER_SOL as SOL, PublicKey, SystemProgram, Transaction } from "@solana/web3.js";
import { KeypairWallet, SolanaAgentKit, createVercelAITools, executeAction } from "solana-agent-kit";
import nacl from "tweetnacl";

import { HyperionGuardPlugin } from "../src/agent-kit.ts";
import { GuardClient, initializeIx, vaultAddress, withdrawIx } from "../src/index.ts";

const GUARD_URL = process.env.HYPERION_GUARD_URL ?? "https://hyperion-guard-dijsyl2kwq-uc.a.run.app";
const RPC = process.env.SOLANA_RPC_URL ?? "https://api.devnet.solana.com";
const PROGRAM = new PublicKey(process.env.HYPERION_VAULT_PROGRAM_ID ?? "9btLSADcT2u3M1HnC4cdkV4HiN662bqmhHYvevaSragq");
const KEYPAIR = (process.env.SOLANA_KEYPAIR ?? "~/.config/solana/id.json").replace(/^~/, homedir());
const WSOL = "So11111111111111111111111111111111111111112";

const owner = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(KEYPAIR, "utf8"))));
const agentKey = Keypair.generate();
const merchant = Keypair.generate().publicKey;
const agentId = `agent-kit-demo-${agentKey.publicKey.toBase58().slice(0, 8)}`;
const link = (signature: string) => `https://explorer.solana.com/tx/${signature}?cluster=devnet`;
const scene = (n: number, title: string) => console.log(`\n── ${n}. ${title} ${"─".repeat(Math.max(0, 66 - title.length))}`);

// The agent: a stock SolanaAgentKit, its wallet the agent's own key, with the plugin.
const agent = new SolanaAgentKit(new KeypairWallet(agentKey, RPC), RPC, {})
  .use(HyperionGuardPlugin({ guardUrl: GUARD_URL, programId: PROGRAM, owner: owner.publicKey, agentId }));
const { connection } = agent;
const act = (name: string, input: Record<string, unknown>) => executeAction(agent.actions.find((a) => a.name === name)!, agent, input);

const price = ((await (await fetch(`https://lite-api.jup.ag/price/v3?ids=${WSOL}`, { headers: { "user-agent": "hyperion-guard" } })).json()) as
  Record<string, { usdPrice: number }>)[WSOL]!.usdPrice;
const capUsd = Math.round((price / 30) * 100) / 100;                // worth 0.0333 SOL: 0.02 fits, 0.04 doesn't

console.log(`agent kit solana-agent-kit, with the hyperion-guard plugin
LLM tools ${agent.actions.filter((a) => a.name.startsWith("HYPERION")).map((a) => a.name).join(", ")} (${Object.keys(createVercelAITools(agent, agent.actions)).length} tools in all)
owner     ${owner.publicKey.toBase58()}
agent     ${agentKey.publicKey.toBase58()}
Guard     ${GUARD_URL}
SOL       $${price.toFixed(2)}`);

scene(1, "The owner opens a vault for the agent and sets its policy");
{
  const guard = new GuardClient(GUARD_URL);
  const guardKey = await guard.cosignerKey();
  const [vault] = vaultAddress(PROGRAM, owner.publicKey, agentKey.publicKey);
  const { blockhash } = await connection.getLatestBlockhash();
  const tx = new Transaction({ feePayer: owner.publicKey, recentBlockhash: blockhash }).add(
    initializeIx(PROGRAM, owner.publicKey, agentKey.publicKey, { guardian: owner.publicKey, guard: guardKey, maxLamportsPerTx: SOL / 20 }),
    SystemProgram.transfer({ fromPubkey: owner.publicKey, toPubkey: vault, lamports: SOL / 10 }),             // the agent's working money
    SystemProgram.transfer({ fromPubkey: owner.publicKey, toPubkey: agentKey.publicKey, lamports: SOL / 100 }), // its own fees, all its wallet holds
  );
  tx.sign(owner);
  const signature = await connection.sendRawTransaction(tx.serialize());
  await connection.confirmTransaction(signature, "confirmed");
  const now = Math.floor(Date.now() / 1000);
  await guard.setPolicy(
    { agentId, agent: agentKey.publicKey, owner: owner.publicKey, maxOrderNotionalUsd: capUsd, maxSlippageBps: 100,
      policyVersion: now, nonce: now, allowedPrograms: [PROGRAM], vaultAddress: vault },
    (message) => nacl.sign.detached(message, owner.secretKey),
  );
  console.log(`   Guard policy: $${capUsd.toFixed(2)} an order\n   ${link(signature)}`);
}

scene(2, "The agent checks its vault (HYPERION_GUARD_VAULT_INFO)");
console.log("  ", await act("HYPERION_GUARD_VAULT_INFO", {}));

scene(3, "The agent pays 0.02 SOL (HYPERION_GUARDED_TRANSFER_SOL)");
{
  const result = await act("HYPERION_GUARDED_TRANSFER_SOL", { to: merchant.toBase58(), amountSol: 0.02 });
  if (result.status !== "success") throw new Error(JSON.stringify(result));
  console.log(`   ${result.status}: the Guard co-signed; the merchant has ${(await connection.getBalance(merchant)) / SOL} SOL\n   ${link(result.signature)}`);
}

scene(4, "The agent tries 0.04 SOL, over the owner's dollar cap");
{
  const result = await act("HYPERION_GUARDED_TRANSFER_SOL", { to: merchant.toBase58(), amountSol: 0.04 });
  if (result.status !== "refused") throw new Error(`the Guard signed an order over the cap: ${JSON.stringify(result)}`);
  console.log(`   what the model is told:`, result, `\n   the merchant still has ${(await connection.getBalance(merchant)) / SOL} SOL`);
}

scene(5, "The owner takes the rest back");
{
  const info = await agent.methods.guardVaultInfo(agent);
  const account = await connection.getAccountInfo(info.address);
  const spare = account!.lamports - (await connection.getMinimumBalanceForRentExemption(account!.data.length));
  const { blockhash } = await connection.getLatestBlockhash();
  const tx = new Transaction({ feePayer: owner.publicKey, recentBlockhash: blockhash })
    .add(withdrawIx(PROGRAM, owner.publicKey, info.address, owner.publicKey, spare));
  tx.sign(owner);
  const signature = await connection.sendRawTransaction(tx.serialize());
  await connection.confirmTransaction(signature, "confirmed");
  console.log(`   withdrew ${(spare / SOL).toFixed(4)} SOL\n   ${link(signature)}`);
  console.log(`\nvault: https://explorer.solana.com/address/${info.address.toBase58()}?cluster=devnet`);
}
