# Hyperion Guarded Vault (Solana)

A native Solana program where an autonomous trading agent's funds sit in a
vault, and **every agent action needs the Hyperion Guard's co-signature**,
enforced on-chain.

**Why a co-signature is enough on Solana.** A Solana signature covers the
whole transaction message. When the Guard co-signs, it approves exactly the
instructions it decoded and checked (size, slippage, programs, kill switch),
and nothing can be swapped in afterwards. The vault makes that co-signature
mandatory, and keeps the owner's controls out of the agent's reach.

| Instruction | Signers | Rules |
|---|---|---|
| `Initialize` | owner | Creates the vault at PDA `["hyperion-vault", owner, agent]` with its policy |
| `TransferSol` | agent + Guard | Not killed; within the per-transaction cap; never below the rent-exempt minimum |
| `Execute` | agent + Guard | Not killed; target on the owner's allow-list (never this program); the vault signs the inner call as a PDA, so it can be the authority of its token accounts |
| `Kill` | owner or guardian | Stops all agent actions |
| `Revive` | owner | The guardian can't revive |
| `SetPolicy` | owner | Guardian, Guard key, cap, allow-list |
| `Withdraw` / `OwnerExecute` | owner | Work even when killed, so funds are never stuck |

The account layout is in [`src/state.rs`](src/state.rs), the encoding in
[`src/instruction.rs`](src/instruction.rs), and the rules in
[`src/processor.rs`](src/processor.rs).

## Build and test

You need [`cargo-build-sbf`](https://crates.io/crates/cargo-build-sbf):

```bash
cargo install --locked cargo-build-sbf
```

Then, from this folder:

```bash
cargo build-sbf
```

```bash
cargo test
```

`cargo test` runs 5 unit tests and 9 integration tests that load the
compiled `target/deploy/hyperion_solana_vault.so` into
[LiteSVM](https://crates.io/crates/litesvm) and send real transactions.

- **What's covered:** a missing or faked Guard signature, a stranger posing as
  the agent, the cap and the rent floor, kill and revive roles, owner-only
  policy and withdrawal (also while killed), PDA-signed calls to allowed
  programs, and refusal of others and of the vault itself.
- **Mutation check:** removing the Guard-signature check makes two of these
  tests fail.

`rust-toolchain.toml` pins the host toolchain for the tests, because
LiteSVM's dependencies need Rust 1.97 or later. The on-chain build uses
`cargo build-sbf`'s own compiler.

## Not yet

- **Not deployed to devnet yet.**
- **Token amounts aren't capped on-chain.** Only SOL is (`TransferSol`). Token
  sizes inside `Execute` rely on the Guard's co-signature over the exact
  instruction.
- **Not audited.**
