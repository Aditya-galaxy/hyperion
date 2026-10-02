//! The vault account's layout. Plain bytes, little-endian, no framework, so
//! any client can read it.
//!
//! | offset | size | field |
//! |---|---|---|
//! | 0 | 1 | initialized (1) |
//! | 1 | 1 | killed (1) |
//! | 2 | 1 | PDA bump |
//! | 3 | 32 | owner |
//! | 35 | 32 | guardian (all zeros: none) |
//! | 67 | 32 | agent |
//! | 99 | 32 | guard co-signer |
//! | 131 | 8 | max lamports per TransferSol |
//! | 139 | 8 | executions (count of agent actions that went through) |
//! | 147 | 1 | number of allowed programs (≤ 8) |
//! | 148 | 256 | allowed program ids |

pub const MAX_PROGRAMS: usize = 8;
pub const VAULT_LEN: usize = 148 + 32 * MAX_PROGRAMS; // 404
pub const SEED: &[u8] = b"hyperion-vault";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vault {
    pub killed: bool,
    pub bump: u8,
    pub owner: [u8; 32],
    pub guardian: [u8; 32],
    pub agent: [u8; 32],
    pub guard_cosigner: [u8; 32],
    pub max_lamports_per_tx: u64,
    pub executions: u64,
    pub allowed_programs: Vec<[u8; 32]>,
}

fn key(src: &[u8], at: usize) -> [u8; 32] {
    let mut k = [0u8; 32];
    k.copy_from_slice(&src[at..at + 32]);
    k
}

impl Vault {
    pub fn has_guardian(&self) -> bool {
        self.guardian != [0u8; 32]
    }

    pub fn allows(&self, program: &[u8; 32]) -> bool {
        self.allowed_programs.iter().any(|p| p == program)
    }

    /// None if the bytes aren't an initialized vault.
    pub fn unpack(src: &[u8]) -> Option<Self> {
        if src.len() < VAULT_LEN || src[0] != 1 {
            return None;
        }
        let n = src[147] as usize;
        if n > MAX_PROGRAMS {
            return None;
        }
        Some(Self {
            killed: src[1] != 0,
            bump: src[2],
            owner: key(src, 3),
            guardian: key(src, 35),
            agent: key(src, 67),
            guard_cosigner: key(src, 99),
            max_lamports_per_tx: u64::from_le_bytes(src[131..139].try_into().ok()?),
            executions: u64::from_le_bytes(src[139..147].try_into().ok()?),
            allowed_programs: (0..n).map(|i| key(src, 148 + 32 * i)).collect(),
        })
    }

    pub fn pack(&self, dst: &mut [u8]) {
        assert!(dst.len() >= VAULT_LEN && self.allowed_programs.len() <= MAX_PROGRAMS);
        dst[..VAULT_LEN].fill(0);
        dst[0] = 1;
        dst[1] = self.killed as u8;
        dst[2] = self.bump;
        dst[3..35].copy_from_slice(&self.owner);
        dst[35..67].copy_from_slice(&self.guardian);
        dst[67..99].copy_from_slice(&self.agent);
        dst[99..131].copy_from_slice(&self.guard_cosigner);
        dst[131..139].copy_from_slice(&self.max_lamports_per_tx.to_le_bytes());
        dst[139..147].copy_from_slice(&self.executions.to_le_bytes());
        dst[147] = self.allowed_programs.len() as u8;
        for (i, p) in self.allowed_programs.iter().enumerate() {
            dst[148 + 32 * i..180 + 32 * i].copy_from_slice(p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let v = Vault {
            killed: true,
            bump: 254,
            owner: [1; 32],
            guardian: [2; 32],
            agent: [3; 32],
            guard_cosigner: [4; 32],
            max_lamports_per_tx: 5_000_000,
            executions: 7,
            allowed_programs: vec![[9; 32], [8; 32]],
        };
        let mut buf = vec![0u8; VAULT_LEN];
        v.pack(&mut buf);
        assert_eq!(Vault::unpack(&buf), Some(v));
    }

    #[test]
    fn uninitialized_or_short_is_none() {
        assert_eq!(Vault::unpack(&[0u8; VAULT_LEN]), None);
        assert_eq!(Vault::unpack(&[1u8; 10]), None);
    }
}
