//! The vault program's instructions.
//!
//! A Solana signature covers the whole transaction message. So when the
//! Hyperion Guard co-signs, it approves exactly the instructions it was shown,
//! and nothing can be swapped in afterwards. What this program adds is the
//! part the Guard can't do off-chain: it makes the Guard's signature
//! *mandatory* for anything the agent does with the vault's funds, and it
//! keeps the owner's controls (kill, revive, policy, withdrawal) out of the
//! agent's reach.
//!
//! Agent actions (TransferSol, Execute) need, every time:
//!   * the agent's signature and the Guard co-signer's signature;
//!   * a vault that isn't killed;
//!   * for TransferSol, an amount within the owner's per-transaction cap, never
//!     dipping below the rent-exempt minimum;
//!   * for Execute, a target program on the owner's allow-list (never this
//!     program itself). The vault signs the inner call as a PDA, so it can act
//!     as the authority of its own token accounts.
//!
//! The owner can always Withdraw or OwnerExecute, killed or not, so funds are
//! never stuck behind the Guard. The guardian can only Kill.

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
};

use crate::instruction::{Policy, VaultInstruction};
use crate::state::{Vault, SEED, VAULT_LEN};

/// Custom error codes, returned as `ProgramError::Custom(code)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum VaultError {
    NotOwner = 1,
    NotAgent = 2,
    MissingGuardCoSignature = 3,
    VaultKilled = 4,
    OverCap = 5,
    ProgramNotAllowed = 6,
    NotOwnerOrGuardian = 7,
    GuardianCannotRevive = 8,
    WrongVaultAddress = 9,
    BelowRentExempt = 10,
    AlreadyInitialized = 11,
    NotAVault = 12,
}

impl From<VaultError> for ProgramError {
    fn from(e: VaultError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let ix = VaultInstruction::unpack(data).ok_or(ProgramError::InvalidInstructionData)?;
    match ix {
        VaultInstruction::Initialize { agent, policy } => initialize(program_id, accounts, agent, policy),
        VaultInstruction::TransferSol { lamports } => transfer_sol(program_id, accounts, lamports),
        VaultInstruction::Execute { data } => execute(program_id, accounts, &data, false),
        VaultInstruction::OwnerExecute { data } => execute(program_id, accounts, &data, true),
        VaultInstruction::Kill => kill(program_id, accounts),
        VaultInstruction::Revive => revive(program_id, accounts),
        VaultInstruction::SetPolicy { policy } => set_policy(program_id, accounts, policy),
        VaultInstruction::Withdraw { lamports } => withdraw(program_id, accounts, lamports),
    }
}

fn load(program_id: &Pubkey, vault: &AccountInfo) -> Result<Vault, ProgramError> {
    if vault.owner != program_id {
        return Err(VaultError::NotAVault.into());
    }
    Vault::unpack(&vault.try_borrow_data()?).ok_or_else(|| VaultError::NotAVault.into())
}

fn store(vault_info: &AccountInfo, vault: &Vault) -> ProgramResult {
    vault.pack(&mut vault_info.try_borrow_mut_data()?);
    Ok(())
}

fn signed_by(info: &AccountInfo, key: &[u8; 32]) -> bool {
    info.is_signer && info.key.to_bytes() == *key
}

fn apply(vault: &mut Vault, policy: Policy) {
    vault.guardian = policy.guardian;
    vault.guard_cosigner = policy.guard_cosigner;
    vault.max_lamports_per_tx = policy.max_lamports_per_tx;
    vault.allowed_programs = policy.allowed_programs;
}

/// accounts: owner (signer, writable, pays), vault PDA (writable), system program
fn initialize(program_id: &Pubkey, accounts: &[AccountInfo], agent: [u8; 32], policy: Policy) -> ProgramResult {
    let it = &mut accounts.iter();
    let owner = next_account_info(it)?;
    let vault_info = next_account_info(it)?;
    let system_program = next_account_info(it)?;
    if !owner.is_signer {
        return Err(VaultError::NotOwner.into());
    }
    let (pda, bump) = Pubkey::find_program_address(&[SEED, owner.key.as_ref(), &agent], program_id);
    if *vault_info.key != pda {
        return Err(VaultError::WrongVaultAddress.into());
    }
    if !vault_info.data_is_empty() {
        return Err(VaultError::AlreadyInitialized.into());
    }
    let rent = Rent::get()?.minimum_balance(VAULT_LEN);
    let create = solana_system_interface::instruction::create_account(
        owner.key,
        vault_info.key,
        rent,
        VAULT_LEN as u64,
        program_id,
    );
    invoke_signed(
        &create,
        &[owner.clone(), vault_info.clone(), system_program.clone()],
        &[&[SEED, owner.key.as_ref(), &agent, &[bump]]],
    )?;
    let mut vault = Vault {
        killed: false,
        bump,
        owner: owner.key.to_bytes(),
        guardian: [0; 32],
        agent,
        guard_cosigner: [0; 32],
        max_lamports_per_tx: 0,
        executions: 0,
        allowed_programs: vec![],
    };
    apply(&mut vault, policy);
    store(vault_info, &vault)?;
    msg!("hyperion vault initialized");
    Ok(())
}

/// The checks every agent action shares.
fn check_agent_action(vault: &Vault, agent: &AccountInfo, guard: &AccountInfo) -> ProgramResult {
    if vault.killed {
        return Err(VaultError::VaultKilled.into());
    }
    if !signed_by(agent, &vault.agent) {
        return Err(VaultError::NotAgent.into());
    }
    if !signed_by(guard, &vault.guard_cosigner) {
        return Err(VaultError::MissingGuardCoSignature.into());
    }
    Ok(())
}

fn move_lamports(vault_info: &AccountInfo, to: &AccountInfo, lamports: u64) -> ProgramResult {
    let floor = Rent::get()?.minimum_balance(VAULT_LEN);
    let left = vault_info.lamports().checked_sub(lamports).ok_or(ProgramError::InsufficientFunds)?;
    if left < floor {
        return Err(VaultError::BelowRentExempt.into());
    }
    **vault_info.try_borrow_mut_lamports()? = left;
    let credited = to.lamports().checked_add(lamports).ok_or(ProgramError::ArithmeticOverflow)?;
    **to.try_borrow_mut_lamports()? = credited;
    Ok(())
}

/// accounts: agent (signer), guard co-signer (signer), vault (writable), destination (writable)
fn transfer_sol(program_id: &Pubkey, accounts: &[AccountInfo], lamports: u64) -> ProgramResult {
    let it = &mut accounts.iter();
    let agent = next_account_info(it)?;
    let guard = next_account_info(it)?;
    let vault_info = next_account_info(it)?;
    let dest = next_account_info(it)?;
    let mut vault = load(program_id, vault_info)?;
    check_agent_action(&vault, agent, guard)?;
    if lamports > vault.max_lamports_per_tx {
        return Err(VaultError::OverCap.into());
    }
    move_lamports(vault_info, dest, lamports)?;
    vault.executions += 1;
    store(vault_info, &vault)
}

/// Agent (`owner_mode = false`) accounts: agent (signer), guard co-signer (signer),
/// vault (writable), target program, then the inner instruction's accounts.
/// Owner (`owner_mode = true`) accounts: owner (signer), vault, target program,
/// then the inner instruction's accounts. The owner bypasses the kill switch
/// and the allow-list: it's how funds get out whatever the agent's state.
fn execute(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8], owner_mode: bool) -> ProgramResult {
    let it = &mut accounts.iter();
    let first = next_account_info(it)?;
    let guard = if owner_mode { None } else { Some(next_account_info(it)?) };
    let vault_info = next_account_info(it)?;
    let target = next_account_info(it)?;
    let inner: Vec<AccountInfo> = it.cloned().collect();

    let mut vault = load(program_id, vault_info)?;
    if owner_mode {
        if !signed_by(first, &vault.owner) {
            return Err(VaultError::NotOwner.into());
        }
    } else {
        check_agent_action(&vault, first, guard.unwrap())?;
        if !vault.allows(&target.key.to_bytes()) {
            return Err(VaultError::ProgramNotAllowed.into());
        }
        vault.executions += 1;
    }
    if target.key == program_id {
        return Err(VaultError::ProgramNotAllowed.into()); // no re-entry into the vault itself
    }
    store(vault_info, &vault)?; // before the call, and the borrow ends here

    let metas = inner
        .iter()
        .map(|a| AccountMeta {
            pubkey: *a.key,
            is_signer: a.is_signer || a.key == vault_info.key,
            is_writable: a.is_writable,
        })
        .collect();
    let call = Instruction { program_id: *target.key, accounts: metas, data: data.to_vec() };
    let mut infos = vec![vault_info.clone(), target.clone()];
    infos.extend(inner.iter().cloned());
    invoke_signed(&call, &infos, &[&[SEED, &vault.owner, &vault.agent, &[vault.bump]]])
}

/// accounts: caller (signer: owner or guardian), vault (writable)
fn kill(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let it = &mut accounts.iter();
    let caller = next_account_info(it)?;
    let vault_info = next_account_info(it)?;
    let mut vault = load(program_id, vault_info)?;
    let guardian_ok = vault.has_guardian() && signed_by(caller, &vault.guardian);
    if !(signed_by(caller, &vault.owner) || guardian_ok) {
        return Err(VaultError::NotOwnerOrGuardian.into());
    }
    vault.killed = true;
    msg!("hyperion vault killed");
    store(vault_info, &vault)
}

/// accounts: owner (signer), vault (writable)
fn revive(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let it = &mut accounts.iter();
    let caller = next_account_info(it)?;
    let vault_info = next_account_info(it)?;
    let mut vault = load(program_id, vault_info)?;
    if !signed_by(caller, &vault.owner) {
        let guardian = vault.has_guardian() && signed_by(caller, &vault.guardian);
        return Err(if guardian { VaultError::GuardianCannotRevive } else { VaultError::NotOwner }.into());
    }
    vault.killed = false;
    store(vault_info, &vault)
}

/// accounts: owner (signer), vault (writable)
fn set_policy(program_id: &Pubkey, accounts: &[AccountInfo], policy: Policy) -> ProgramResult {
    let it = &mut accounts.iter();
    let caller = next_account_info(it)?;
    let vault_info = next_account_info(it)?;
    let mut vault = load(program_id, vault_info)?;
    if !signed_by(caller, &vault.owner) {
        return Err(VaultError::NotOwner.into());
    }
    apply(&mut vault, policy);
    store(vault_info, &vault)
}

/// accounts: owner (signer), vault (writable), destination (writable)
fn withdraw(program_id: &Pubkey, accounts: &[AccountInfo], lamports: u64) -> ProgramResult {
    let it = &mut accounts.iter();
    let caller = next_account_info(it)?;
    let vault_info = next_account_info(it)?;
    let dest = next_account_info(it)?;
    let vault = load(program_id, vault_info)?;
    if !signed_by(caller, &vault.owner) {
        return Err(VaultError::NotOwner.into());
    }
    move_lamports(vault_info, dest, lamports)
}
