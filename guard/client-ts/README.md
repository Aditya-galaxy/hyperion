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
npm test          # 14 tests
npm run demo      # six scenes on devnet, against the hosted Guard
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

## What's here

| | |
|---|---|
| `vaultAddress` | The vault's address for an owner and an agent |
| `initializeIx` | The owner opens a vault |
| `transferSolIx`, `executeIx` | The agent's two actions; both need the Guard's signature |
| `killIx`, `reviveIx`, `withdrawIx` | The guardian's and the owner's controls |
| `GuardClient` | `cosignerKey`, `setPolicy`, `check`, `checkAndCosign`, `kill`, `revive` |
| `policyMessage`, `actionMessage` | The exact bytes an owner or guardian signs |

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
