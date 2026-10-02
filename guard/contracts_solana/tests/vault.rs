//! The vault program, compiled to SBF and run in LiteSVM. Build it first:
//!     cargo build-sbf && cargo test
//!
//! Each test drives real transactions through the program and checks what
//! the chain would do: who can move funds, and what's refused.

use std::str::FromStr;

use litesvm::LiteSVM;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

const SEED: &[u8] = b"hyperion-vault";
const SO: &str = "target/deploy/hyperion_solana_vault.so";
const SOL: u64 = 1_000_000_000;

// error codes from processor::VaultError
const NOT_OWNER: u32 = 1;
const NOT_AGENT: u32 = 2;
const MISSING_GUARD: u32 = 3;
const KILLED: u32 = 4;
const OVER_CAP: u32 = 5;
const NOT_ALLOWED: u32 = 6;
const NOT_OWNER_OR_GUARDIAN: u32 = 7;
const GUARDIAN_CANNOT_REVIVE: u32 = 8;
const WRONG_ADDRESS: u32 = 9;
const BELOW_RENT: u32 = 10;
const ALREADY_INIT: u32 = 11;

fn system_program() -> Pubkey {
    Pubkey::from_str("11111111111111111111111111111111").unwrap()
}
fn memo_program() -> Pubkey {
    Pubkey::from_str("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr").unwrap()
}

struct World {
    svm: LiteSVM,
    program: Pubkey,
    owner: Keypair,
    guardian: Keypair,
    agent: Keypair,
    guard: Keypair,
    stranger: Keypair,
    vault: Pubkey,
}

fn policy_bytes(guardian: &Pubkey, guard: &Pubkey, max_lamports: u64, programs: &[Pubkey]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(guardian.as_ref());
    v.extend_from_slice(guard.as_ref());
    v.extend_from_slice(&max_lamports.to_le_bytes());
    v.push(programs.len() as u8);
    for p in programs {
        v.extend_from_slice(p.as_ref());
    }
    v
}

impl World {
    fn new() -> Self {
        let mut svm = LiteSVM::new();
        let program = Pubkey::new_unique();
        svm.add_program_from_file(program, SO).expect("build the program first: cargo build-sbf");
        let (owner, guardian, agent, guard, stranger) =
            (Keypair::new(), Keypair::new(), Keypair::new(), Keypair::new(), Keypair::new());
        for k in [&owner, &guardian, &agent, &guard, &stranger] {
            svm.airdrop(&k.pubkey(), 10 * SOL).unwrap();
        }
        let (vault, _) =
            Pubkey::find_program_address(&[SEED, owner.pubkey().as_ref(), agent.pubkey().as_ref()], &program);
        let mut w = World { svm, program, owner, guardian, agent, guard, stranger, vault };
        let ix = w.initialize_ix(&w.vault.clone(), 2 * SOL, &[memo_program()]);
        w.send(ix, &[&w.owner.insecure_clone()]).expect("initialize");
        w.svm.airdrop(&w.vault, 5 * SOL).unwrap(); // fund the vault
        w
    }

    fn initialize_ix(&self, vault: &Pubkey, max_lamports: u64, programs: &[Pubkey]) -> Instruction {
        let mut data = vec![0u8];
        data.extend_from_slice(self.guardian.pubkey().as_ref());
        data.extend_from_slice(self.agent.pubkey().as_ref());
        data.extend_from_slice(&policy_bytes(&self.guardian.pubkey(), &self.guard.pubkey(), max_lamports, programs)[32..]);
        Instruction::new_with_bytes(self.program, &data, vec![
            AccountMeta::new(self.owner.pubkey(), true),
            AccountMeta::new(*vault, false),
            AccountMeta::new_readonly(system_program(), false),
        ])
    }

    /// TransferSol, with `guard_signer` as the account in the co-signer slot.
    fn transfer_ix(&self, guard_key: Pubkey, guard_signs: bool, lamports: u64, to: Pubkey) -> Instruction {
        let mut data = vec![1u8];
        data.extend_from_slice(&lamports.to_le_bytes());
        Instruction::new_with_bytes(self.program, &data, vec![
            AccountMeta::new_readonly(self.agent.pubkey(), true),
            AccountMeta::new_readonly(guard_key, guard_signs),
            AccountMeta::new(self.vault, false),
            AccountMeta::new(to, false),
        ])
    }

    fn execute_memo_ix(&self, target: Pubkey, owner_mode: bool) -> Instruction {
        let mut data = vec![if owner_mode { 7u8 } else { 2u8 }];
        data.extend_from_slice(b"hyperion");
        let mut accounts = if owner_mode {
            vec![AccountMeta::new_readonly(self.owner.pubkey(), true)]
        } else {
            vec![
                AccountMeta::new_readonly(self.agent.pubkey(), true),
                AccountMeta::new_readonly(self.guard.pubkey(), true),
            ]
        };
        accounts.extend([
            AccountMeta::new(self.vault, false),
            AccountMeta::new_readonly(target, false),
            AccountMeta::new_readonly(self.vault, false), // the memo's signer: the vault, via the PDA
        ]);
        Instruction::new_with_bytes(self.program, &data, accounts)
    }

    fn simple_ix(&self, tag: u8, caller: &Pubkey) -> Instruction {
        Instruction::new_with_bytes(self.program, &[tag], vec![
            AccountMeta::new_readonly(*caller, true),
            AccountMeta::new(self.vault, false),
        ])
    }

    fn send(&mut self, ix: Instruction, signers: &[&Keypair]) -> Result<(), Option<u32>> {
        self.svm.expire_blockhash();
        let payer = signers[0].pubkey();
        let tx = Transaction::new(signers, Message::new(&[ix], Some(&payer)), self.svm.latest_blockhash());
        match self.svm.send_transaction(tx) {
            Ok(_) => Ok(()),
            Err(failed) => {
                let text = format!("{:?}", failed.err);
                // InstructionError(0, Custom(N)) → Some(N); anything else → None
                let code = text.split("Custom(").nth(1).and_then(|r| r.split(')').next()).and_then(|n| n.parse().ok());
                Err(code)
            }
        }
    }

    fn balance(&self, k: &Pubkey) -> u64 {
        self.svm.get_balance(k).unwrap_or(0)
    }

    fn vault_bytes(&self) -> Vec<u8> {
        self.svm.get_account(&self.vault).unwrap().data
    }
}

#[test]
fn initialize_stores_the_policy_at_the_pda() {
    let w = World::new();
    let data = w.vault_bytes();
    assert_eq!(data.len(), 404);
    assert_eq!(data[0], 1); // initialized
    assert_eq!(&data[3..35], w.owner.pubkey().as_ref());
    assert_eq!(&data[67..99], w.agent.pubkey().as_ref());
    assert_eq!(&data[99..131], w.guard.pubkey().as_ref());
    assert_eq!(u64::from_le_bytes(data[131..139].try_into().unwrap()), 2 * SOL);
    assert_eq!(w.svm.get_account(&w.vault).unwrap().owner, w.program);
}

#[test]
fn initialize_refuses_a_second_time_and_a_wrong_address() {
    let mut w = World::new();
    let again = w.initialize_ix(&w.vault.clone(), SOL, &[]);
    assert_eq!(w.send(again, &[&w.owner.insecure_clone()]), Err(Some(ALREADY_INIT)));
    let elsewhere = w.initialize_ix(&Pubkey::new_unique(), SOL, &[]);
    assert_eq!(w.send(elsewhere, &[&w.owner.insecure_clone()]), Err(Some(WRONG_ADDRESS)));
}

#[test]
fn agent_and_guard_together_move_funds() {
    let mut w = World::new();
    let to = Pubkey::new_unique();
    let ix = w.transfer_ix(w.guard.pubkey(), true, SOL, to);
    w.send(ix, &[&w.agent.insecure_clone(), &w.guard.insecure_clone()]).unwrap();
    assert_eq!(w.balance(&to), SOL);
    assert_eq!(u64::from_le_bytes(w.vault_bytes()[139..147].try_into().unwrap()), 1); // executions
}

#[test]
fn without_the_guard_nothing_moves() {
    let mut w = World::new();
    let to = Pubkey::new_unique();
    // the guard's key is there but it didn't sign
    let unsigned = w.transfer_ix(w.guard.pubkey(), false, SOL, to);
    assert_eq!(w.send(unsigned, &[&w.agent.insecure_clone()]), Err(Some(MISSING_GUARD)));
    // the agent signs as its own "guard"
    let fake = w.transfer_ix(w.agent.pubkey(), true, SOL, to);
    assert_eq!(w.send(fake, &[&w.agent.insecure_clone()]), Err(Some(MISSING_GUARD)));
    // a stranger with the guard's help isn't the agent
    let mut data = vec![1u8];
    data.extend_from_slice(&SOL.to_le_bytes());
    let stranger_ix = Instruction::new_with_bytes(w.program, &data, vec![
        AccountMeta::new_readonly(w.stranger.pubkey(), true),
        AccountMeta::new_readonly(w.guard.pubkey(), true),
        AccountMeta::new(w.vault, false),
        AccountMeta::new(to, false),
    ]);
    assert_eq!(w.send(stranger_ix, &[&w.stranger.insecure_clone(), &w.guard.insecure_clone()]), Err(Some(NOT_AGENT)));
    assert_eq!(w.balance(&to), 0);
}

#[test]
fn cap_and_rent_floor_hold() {
    let mut w = World::new();
    let to = Pubkey::new_unique();
    let over = w.transfer_ix(w.guard.pubkey(), true, 2 * SOL + 1, to);
    assert_eq!(w.send(over, &[&w.agent.insecure_clone(), &w.guard.insecure_clone()]), Err(Some(OVER_CAP)));
    // raise the cap past the balance: the rent floor still stops a drain
    let raise = Instruction::new_with_bytes(w.program, &[&[5u8][..], &policy_bytes(&w.guardian.pubkey(), &w.guard.pubkey(), 100 * SOL, &[])].concat(), vec![
        AccountMeta::new_readonly(w.owner.pubkey(), true),
        AccountMeta::new(w.vault, false),
    ]);
    w.send(raise, &[&w.owner.insecure_clone()]).unwrap();
    let all = w.balance(&w.vault);
    let drain = w.transfer_ix(w.guard.pubkey(), true, all, to);
    assert_eq!(w.send(drain, &[&w.agent.insecure_clone(), &w.guard.insecure_clone()]), Err(Some(BELOW_RENT)));
}

#[test]
fn kill_by_guardian_revive_by_owner_only() {
    let mut w = World::new();
    let to = Pubkey::new_unique();
    // a stranger can't kill
    let stranger_kill = w.simple_ix(3, &w.stranger.pubkey());
    assert_eq!(w.send(stranger_kill, &[&w.stranger.insecure_clone()]), Err(Some(NOT_OWNER_OR_GUARDIAN)));
    // the guardian kills
    let kill = w.simple_ix(3, &w.guardian.pubkey());
    w.send(kill, &[&w.guardian.insecure_clone()]).unwrap();
    // now even agent + guard can't move funds
    let ix = w.transfer_ix(w.guard.pubkey(), true, SOL, to);
    assert_eq!(w.send(ix, &[&w.agent.insecure_clone(), &w.guard.insecure_clone()]), Err(Some(KILLED)));
    // the guardian and the agent can't revive
    let g_revive = w.simple_ix(4, &w.guardian.pubkey());
    assert_eq!(w.send(g_revive, &[&w.guardian.insecure_clone()]), Err(Some(GUARDIAN_CANNOT_REVIVE)));
    let a_revive = w.simple_ix(4, &w.agent.pubkey());
    assert_eq!(w.send(a_revive, &[&w.agent.insecure_clone()]), Err(Some(NOT_OWNER)));
    // the owner can
    let o_revive = w.simple_ix(4, &w.owner.pubkey());
    w.send(o_revive, &[&w.owner.insecure_clone()]).unwrap();
    let ix = w.transfer_ix(w.guard.pubkey(), true, SOL, to);
    w.send(ix, &[&w.agent.insecure_clone(), &w.guard.insecure_clone()]).unwrap();
    assert_eq!(w.balance(&to), SOL);
}

#[test]
fn only_the_owner_sets_policy_or_withdraws_and_withdrawal_works_when_killed() {
    let mut w = World::new();
    let loosen = Instruction::new_with_bytes(w.program, &[&[5u8][..], &policy_bytes(&w.guardian.pubkey(), &w.agent.pubkey(), 100 * SOL, &[])].concat(), vec![
        AccountMeta::new_readonly(w.agent.pubkey(), true),
        AccountMeta::new(w.vault, false),
    ]);
    assert_eq!(w.send(loosen, &[&w.agent.insecure_clone()]), Err(Some(NOT_OWNER))); // the agent can't make itself the guard
    let kill = w.simple_ix(3, &w.owner.pubkey());
    w.send(kill, &[&w.owner.insecure_clone()]).unwrap();
    let to = Pubkey::new_unique();
    let mut data = vec![6u8];
    data.extend_from_slice(&(3 * SOL).to_le_bytes());
    let by_agent = Instruction::new_with_bytes(w.program, &data, vec![
        AccountMeta::new_readonly(w.agent.pubkey(), true),
        AccountMeta::new(w.vault, false),
        AccountMeta::new(to, false),
    ]);
    assert_eq!(w.send(by_agent, &[&w.agent.insecure_clone()]), Err(Some(NOT_OWNER)));
    let by_owner = Instruction::new_with_bytes(w.program, &data, vec![
        AccountMeta::new_readonly(w.owner.pubkey(), true),
        AccountMeta::new(w.vault, false),
        AccountMeta::new(to, false),
    ]);
    w.send(by_owner, &[&w.owner.insecure_clone()]).unwrap();
    assert_eq!(w.balance(&to), 3 * SOL);
}

#[test]
fn execute_signs_as_the_vault_only_for_allowed_programs() {
    let mut w = World::new();
    // memo is on the allow-list: the vault PDA signs the memo
    let ok = w.execute_memo_ix(memo_program(), false);
    w.send(ok, &[&w.agent.insecure_clone(), &w.guard.insecure_clone()]).unwrap();
    // without the guard
    let mut no_guard = w.execute_memo_ix(memo_program(), false);
    no_guard.accounts[1].is_signer = false;
    assert_eq!(w.send(no_guard, &[&w.agent.insecure_clone()]), Err(Some(MISSING_GUARD)));
    // a program not on the list, and the vault program itself
    let other = w.execute_memo_ix(system_program(), false);
    assert_eq!(w.send(other, &[&w.agent.insecure_clone(), &w.guard.insecure_clone()]), Err(Some(NOT_ALLOWED)));
    let itself = w.execute_memo_ix(w.program, false);
    assert_eq!(w.send(itself, &[&w.agent.insecure_clone(), &w.guard.insecure_clone()]), Err(Some(NOT_ALLOWED)));
}

#[test]
fn owner_execute_works_even_when_killed() {
    let mut w = World::new();
    let kill = w.simple_ix(3, &w.guardian.pubkey());
    w.send(kill, &[&w.guardian.insecure_clone()]).unwrap();
    let agent_try = w.execute_memo_ix(memo_program(), false);
    assert_eq!(w.send(agent_try, &[&w.agent.insecure_clone(), &w.guard.insecure_clone()]), Err(Some(KILLED)));
    let owner_ix = w.execute_memo_ix(memo_program(), true);
    w.send(owner_ix, &[&w.owner.insecure_clone()]).unwrap();
    let agent_as_owner = {
        let mut ix = w.execute_memo_ix(memo_program(), true);
        ix.accounts[0].pubkey = w.agent.pubkey();
        ix
    };
    assert_eq!(w.send(agent_as_owner, &[&w.agent.insecure_clone()]), Err(Some(NOT_OWNER)));
}
