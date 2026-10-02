//! HYPERION GUARDED VAULT: THE SOLANA EXECUTION VAULT
//! ===================================================
//! The Solana counterpart to `GuardedExecutor.sol` on Arc: an account an
//! autonomous trading agent trades from, where every agent action needs the
//! Hyperion Guard's co-signature, enforced on-chain.
//!
//! See `processor.rs` for the rules, `instruction.rs` for the encoding and
//! `state.rs` for the account layout.

pub mod instruction;
pub mod processor;
pub mod state;

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint {
    use solana_program::{account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, pubkey::Pubkey};

    entrypoint!(process_instruction);

    fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
        crate::processor::process(program_id, accounts, data)
    }
}
