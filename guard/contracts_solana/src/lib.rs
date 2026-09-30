//! HYPERION GUARDED VAULT: SOLANA ON-CHAIN EXECUTION VAULT
//! ==========================================================
//! The Solana counterpart to `GuardedExecutor.sol` on EVM.
//!
//! An autonomous trading agent cannot trade directly from its treasury.
//! Instead, funds sit in this PDA execution vault. Every transaction
//! requires TWO authorized cryptographic signatures:
//!   1. The Autonomous Agent's key (`agent`)
//!   2. The Hyperion Pre-Trade Guard's key (`guard_cosigner`)
//!
//! Circuit Breakers & Invariants:
//!   - Both `agent` AND `guard_cosigner` MUST be valid transaction signers.
//!   - If `guard_cosigner` withholds its signature, the transaction fails on-chain.
//!   - The `guardian` or `owner` can trip the kill switch instantly.
//!   - The `guardian` CANNOT revive; ONLY the `owner` can revive an agent.
//!   - The agent cannot loosen its own limits or unkill itself.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultError {
    AlreadyInitialized,
    NotInitialized,
    MissingAgentSignature,
    MissingGuardCoSignature,
    UnauthorizedCaller,
    GuardianCannotRevive,
    VaultKilled,
    OrderExceedsNotionalCap,
    InvalidInstructionData,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardedVault {
    pub is_initialized: bool,
    pub is_killed: bool,
    pub owner: [u8; 32],
    pub guardian: [u8; 32],
    pub agent: [u8; 32],
    pub guard_cosigner: [u8; 32],
    pub max_order_notional: u64,
    pub nonce: u64,
}

impl GuardedVault {
    pub const LEN: usize = 1 + 1 + 32 + 32 + 32 + 32 + 8 + 8; // 146 bytes

    pub fn new(
        owner: [u8; 32],
        guardian: [u8; 32],
        agent: [u8; 32],
        guard_cosigner: [u8; 32],
        max_order_notional: u64,
    ) -> Self {
        Self {
            is_initialized: true,
            is_killed: false,
            owner,
            guardian,
            agent,
            guard_cosigner,
            max_order_notional,
            nonce: 0,
        }
    }

    /// Pack into binary buffer
    pub fn pack_into(&self, dst: &mut [u8]) -> Result<(), VaultError> {
        if dst.len() < Self::LEN {
            return Err(VaultError::InvalidInstructionData);
        }
        dst[0] = if self.is_initialized { 1 } else { 0 };
        dst[1] = if self.is_killed { 1 } else { 0 };
        dst[2..34].copy_from_slice(&self.owner);
        dst[34..66].copy_from_slice(&self.guardian);
        dst[66..98].copy_from_slice(&self.agent);
        dst[98..130].copy_from_slice(&self.guard_cosigner);
        dst[130..138].copy_from_slice(&self.max_order_notional.to_le_bytes());
        dst[138..146].copy_from_slice(&self.nonce.to_le_bytes());
        Ok(())
    }

    /// Unpack from binary buffer
    pub fn unpack_from(src: &[u8]) -> Result<Self, VaultError> {
        if src.len() < Self::LEN {
            return Err(VaultError::InvalidInstructionData);
        }
        let is_initialized = src[0] != 0;
        let is_killed = src[1] != 0;
        let mut owner = [0u8; 32];
        owner.copy_from_slice(&src[2..34]);
        let mut guardian = [0u8; 32];
        guardian.copy_from_slice(&src[34..66]);
        let mut agent = [0u8; 32];
        agent.copy_from_slice(&src[66..98]);
        let mut guard_cosigner = [0u8; 32];
        guard_cosigner.copy_from_slice(&src[98..130]);
        let max_order_notional = u64::from_le_bytes(src[130..138].try_into().unwrap());
        let nonce = u64::from_le_bytes(src[138..146].try_into().unwrap());

        Ok(Self {
            is_initialized,
            is_killed,
            owner,
            guardian,
            agent,
            guard_cosigner,
            max_order_notional,
            nonce,
        })
    }

    /// Execute an order through the vault. Requires DUAL signatures:
    ///   - agent must sign
    ///   - guard_cosigner must sign
    pub fn process_execute(
        &mut self,
        agent_signed: bool,
        guard_signed: bool,
        declared_notional: u64,
    ) -> Result<(), VaultError> {
        if !self.is_initialized {
            return Err(VaultError::NotInitialized);
        }
        if self.is_killed {
            return Err(VaultError::VaultKilled);
        }
        if !agent_signed {
            return Err(VaultError::MissingAgentSignature);
        }
        if !guard_signed {
            return Err(VaultError::MissingGuardCoSignature);
        }
        if declared_notional > self.max_order_notional {
            return Err(VaultError::OrderExceedsNotionalCap);
        }

        self.nonce += 1;
        Ok(())
    }

    /// Emergency Kill Switch: Trip execution halt.
    /// Callable by either `owner` OR `guardian`.
    pub fn process_kill(&mut self, caller: &[u8; 32], caller_signed: bool) -> Result<(), VaultError> {
        if !self.is_initialized {
            return Err(VaultError::NotInitialized);
        }
        if !caller_signed {
            return Err(VaultError::UnauthorizedCaller);
        }
        if caller != &self.owner && caller != &self.guardian {
            return Err(VaultError::UnauthorizedCaller);
        }

        self.is_killed = true;
        Ok(())
    }

    /// Owner Revival: Re-enables trading.
    /// Callable ONLY by `owner`. Guardian or agent CANNOT revive.
    pub fn process_revive(&mut self, caller: &[u8; 32], caller_signed: bool) -> Result<(), VaultError> {
        if !self.is_initialized {
            return Err(VaultError::NotInitialized);
        }
        if !caller_signed {
            return Err(VaultError::UnauthorizedCaller);
        }
        if caller == &self.guardian {
            return Err(VaultError::GuardianCannotRevive);
        }
        if caller != &self.owner {
            return Err(VaultError::UnauthorizedCaller);
        }

        self.is_killed = false;
        Ok(())
    }

    /// Policy Update: Adjust size limits.
    /// Callable ONLY by `owner`.
    pub fn process_set_policy(
        &mut self,
        caller: &[u8; 32],
        caller_signed: bool,
        new_max_notional: u64,
    ) -> Result<(), VaultError> {
        if !self.is_initialized {
            return Err(VaultError::NotInitialized);
        }
        if !caller_signed || caller != &self.owner {
            return Err(VaultError::UnauthorizedCaller);
        }

        self.max_order_notional = new_max_notional;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: [u8; 32] = [1u8; 32];
    const GUARDIAN: [u8; 32] = [2u8; 32];
    const AGENT: [u8; 32] = [3u8; 32];
    const GUARD: [u8; 32] = [4u8; 32];
    const STRANGER: [u8; 32] = [9u8; 32];

    #[test]
    fn test_vault_pack_unpack_roundtrip() {
        let vault = GuardedVault::new(OWNER, GUARDIAN, AGENT, GUARD, 10_000_000);
        let mut buf = [0u8; GuardedVault::LEN];
        vault.pack_into(&mut buf).unwrap();

        let unpacked = GuardedVault::unpack_from(&buf).unwrap();
        assert_eq!(vault, unpacked);
    }

    #[test]
    fn test_execute_requires_both_agent_and_guard_signatures() {
        let mut vault = GuardedVault::new(OWNER, GUARDIAN, AGENT, GUARD, 10_000_000);

        // 1. Missing Guard signature -> Reverts!
        let err = vault.process_execute(true, false, 5_000_000).unwrap_err();
        assert_eq!(err, VaultError::MissingGuardCoSignature);
        assert_eq!(vault.nonce, 0);

        // 2. Missing Agent signature -> Reverts!
        let err = vault.process_execute(false, true, 5_000_000).unwrap_err();
        assert_eq!(err, VaultError::MissingAgentSignature);
        assert_eq!(vault.nonce, 0);

        // 3. Both signatures present -> Succeeds!
        assert!(vault.process_execute(true, true, 5_000_000).is_ok());
        assert_eq!(vault.nonce, 1);
    }

    #[test]
    fn test_execute_enforces_order_cap() {
        let mut vault = GuardedVault::new(OWNER, GUARDIAN, AGENT, GUARD, 1_000_000);
        let err = vault.process_execute(true, true, 1_000_001).unwrap_err();
        assert_eq!(err, VaultError::OrderExceedsNotionalCap);
    }

    #[test]
    fn test_guardian_can_kill_but_cannot_revive() {
        let mut vault = GuardedVault::new(OWNER, GUARDIAN, AGENT, GUARD, 10_000_000);

        // Guardian kills agent
        assert!(vault.process_kill(&GUARDIAN, true).is_ok());
        assert!(vault.is_killed);

        // Trading blocked while killed
        let err = vault.process_execute(true, true, 500).unwrap_err();
        assert_eq!(err, VaultError::VaultKilled);

        // Guardian attempts to revive -> Blocked!
        let err = vault.process_revive(&GUARDIAN, true).unwrap_err();
        assert_eq!(err, VaultError::GuardianCannotRevive);
        assert!(vault.is_killed);

        // Stranger attempts to revive -> Blocked!
        let err = vault.process_revive(&STRANGER, true).unwrap_err();
        assert_eq!(err, VaultError::UnauthorizedCaller);

        // Owner revives -> Succeeds!
        assert!(vault.process_revive(&OWNER, true).is_ok());
        assert!(!vault.is_killed);

        // Trading resumes
        assert!(vault.process_execute(true, true, 500).is_ok());
    }

    #[test]
    fn test_agent_cannot_loosen_limits() {
        let mut vault = GuardedVault::new(OWNER, GUARDIAN, AGENT, GUARD, 1_000_000);

        // Agent tries to raise notional cap -> Blocked!
        let err = vault.process_set_policy(&AGENT, true, 50_000_000).unwrap_err();
        assert_eq!(err, VaultError::UnauthorizedCaller);
        assert_eq!(vault.max_order_notional, 1_000_000);

        // Owner raises cap -> Succeeds!
        assert!(vault.process_set_policy(&OWNER, true, 50_000_000).is_ok());
        assert_eq!(vault.max_order_notional, 50_000_000);
    }
}
