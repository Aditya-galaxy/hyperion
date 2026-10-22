# Hyperion Guard, TypeScript client

Build Guarded Vault instructions, ask the Guard about a transaction, and
attach its co-signature. It does what the Python client does
(`guard/service/hyperion_guard/solana`), and is tested against it byte for
byte.

It works with `@solana/web3.js` 1.x: instructions are ordinary
`TransactionInstruction`s, and transactions ordinary `Transaction`s.

```bash
cd guard/client-ts
npm install
npm test                 # 21 tests
npm run demo             # six scenes on devnet, against the hosted Guard
npm run demo:agent-kit   # a Solana Agent Kit agent paying from its vault, on devnet
```

## An agent's payment

The agent's money is in a vault that pays only with two signatures: the
agent's and the Guard's. The agent signs, asks the Guard, and sends.

```ts
import { Connection, PublicKey, Transaction } from "@solana/web3.js";
import { GuardClient, GuardRefused, transferSolIx, vaultAddress } from "hyperion-guard-client";

const guard = new GuardClient("https://hyperion-guard-dijsyl2kwq-uc.a.run.app");
const guardKey = await guard.cosignerKey();
const [vault] = vaultAddress(PROGRAM, owner, agent.publicKey);

const { blockhash } = await connection.getLatestBlockhash();
const tx = new Transaction({ feePayer: agent.publicKey, recentBlockhash: blockhash })
  .add(transferSolIx(PROGRAM, vault, agent.publicKey, guardKey, merchant, 20_000_000n));
tx.partialSign(agent);                           // the Guard's slot is still empty

try {
  await guard.checkAndCosign("agent-1", tx);     // adds the Guard's signature
  await connection.sendRawTransaction(tx.serialize());
} catch (e) {
  if (e instanceof GuardRefused) console.log(e.verdict.status, e.verdict.violation_details);
  else throw e;
}
```

To have the vault call another program, a Jupiter swap or a token transfer
from the vault's own accounts, wrap the instruction:

```ts
tx.add(executeIx(PROGRAM, vault, agent.publicKey, guardKey, swapInstruction));
```

The Guard judges the inner call: its size, its slippage, and whether its
program is allowed.

## In a Solana Agent Kit agent

`hyperion-guard-client/agent-kit` is a plugin for
[Solana Agent Kit](https://github.com/sendaifun/solana-agent-kit) 2.x. The
kit's wallet is the agent's own key, holding only fee money. The agent's
working money sits in its vault, and the plugin is how the agent spends it:
it builds the vault instruction, signs with the kit's wallet, asks the Guard,
and sends only if the Guard co-signs.

```ts
import { KeypairWallet, SolanaAgentKit, createVercelAITools } from "solana-agent-kit";
import { HyperionGuardPlugin } from "hyperion-guard-client/agent-kit";

const agent = new SolanaAgentKit(new KeypairWallet(agentKey, rpc), rpc, {})
  .use(HyperionGuardPlugin({ guardUrl, programId, owner, agentId: "agent-1" }));

await agent.methods.guardedTransferSol(agent, merchant, 0.02);   // throws GuardRefused if the Guard says no
await agent.methods.guardedExecute(agent, [swapInstruction]);    // the vault makes the call
const tools = createVercelAITools(agent, agent.actions);         // or createLangchainTools, createOpenAITools
```

It gives a model two actions:

| | |
|---|---|
| `HYPERION_GUARDED_TRANSFER_SOL` | Pay SOL from the vault. A refusal comes back as `{ status: "refused", guardStatus, reason }`, so the model learns why and nothing is sent |
| `HYPERION_GUARD_VAULT_INFO` | The vault's balance, whether it's killed, and its on-chain cap per payment |

The plugin imports only the kit's types, so it uses whichever copy of
`solana-agent-kit` your agent has. `solana-agent-kit` and `zod` are optional
peer dependencies; the rest of this package doesn't need them.

`examples/agent-kit.ts` runs it on devnet. A model's two calls look like this:

```
HYPERION_GUARDED_TRANSFER_SOL { amountSol: 0.02 }  → success, co-signed and sent
HYPERION_GUARDED_TRANSFER_SOL { amountSol: 0.04 }  → refused: Order notional $4.15 exceeds cap of $3.46
```

## What's here

| | |
|---|---|
| `vaultAddress` | The vault's address for an owner and an agent |
| `initializeIx` | The owner opens a vault |
| `transferSolIx`, `executeIx` | The agent's two actions; both need the Guard's signature |
| `killIx`, `reviveIx`, `withdrawIx` | The guardian's and the owner's controls |
| `GuardClient` | `cosignerKey`, `setPolicy`, `check`, `checkAndCosign`, `kill`, `revive` |
| `policyMessage`, `actionMessage` | The exact bytes an owner or guardian signs |
| `decodeVault` | A vault account's state: killed or not, its keys, its cap |
| `HyperionGuardPlugin` | The Solana Agent Kit plugin, from `hyperion-guard-client/agent-kit` |

`setPolicy`, `kill` and `revive` take a function that signs a message, so the
owner's key can live wherever you keep it:

```ts
await guard.setPolicy(policy, (message) => nacl.sign.detached(message, owner.secretKey));
```

## How it's kept honest

`test/make_vectors.py` builds every instruction and message with the Python
client and writes `test/vectors.json`. The TypeScript tests check this client
against that file. A Python test
(`guard/service/tests/test_ts_client_vectors.py`) checks the file is still
what Python produces. Change an encoding on either side and one of them fails.

`examples/devnet.ts` is the same six scenes as `guard/demo/solana_devnet.py`,
run from TypeScript against the hosted Guard and the deployed program.

## Limits

- `@solana/web3.js` 1.x only, not `@solana/kit`.
- Not published to npm; use it from this folder.
- A dollar cap must have at most two decimal places, so the two languages
  never round it differently.
- Like the rest of the Guard: a prototype on devnet, not audited.
