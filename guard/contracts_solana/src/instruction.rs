//! Instruction encoding: one tag byte, then fixed fields, little-endian.
//!
//! | tag | instruction | data after the tag | signers |
//! |---|---|---|---|
//! | 0 | Initialize | guardian 32, agent 32, guard 32, max_lamports 8, n 1, programs 32·n | owner |
//! | 1 | TransferSol | lamports 8 | agent + guard |
//! | 2 | Execute | inner instruction data (rest) | agent + guard |
//! | 3 | Kill | – | owner or guardian |
//! | 4 | Revive | – | owner |
//! | 5 | SetPolicy | guardian 32, guard 32, max_lamports 8, n 1, programs 32·n | owner |
//! | 6 | Withdraw | lamports 8 | owner |
//! | 7 | OwnerExecute | inner instruction data (rest) | owner |

use crate::state::MAX_PROGRAMS;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub guardian: [u8; 32],
    pub guard_cosigner: [u8; 32],
    pub max_lamports_per_tx: u64,
    pub allowed_programs: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultInstruction {
    Initialize { agent: [u8; 32], policy: Policy },
    TransferSol { lamports: u64 },
    Execute { data: Vec<u8> },
    Kill,
    Revive,
    SetPolicy { policy: Policy },
    Withdraw { lamports: u64 },
    OwnerExecute { data: Vec<u8> },
}

fn key(src: &[u8], at: usize) -> Option<[u8; 32]> {
    src.get(at..at + 32)?.try_into().ok()
}

fn u64_at(src: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(src.get(at..at + 8)?.try_into().ok()?))
}

/// guardian, guard, max_lamports, n, programs — starting at `at`.
fn policy_at(src: &[u8], at: usize) -> Option<Policy> {
    let guardian = key(src, at)?;
    let guard_cosigner = key(src, at + 32)?;
    let max_lamports_per_tx = u64_at(src, at + 64)?;
    let n = *src.get(at + 72)? as usize;
    if n > MAX_PROGRAMS || src.len() != at + 73 + 32 * n {
        return None;
    }
    let allowed_programs = (0..n).map(|i| key(src, at + 73 + 32 * i)).collect::<Option<Vec<_>>>()?;
    Some(Policy { guardian, guard_cosigner, max_lamports_per_tx, allowed_programs })
}

impl VaultInstruction {
    pub fn unpack(data: &[u8]) -> Option<Self> {
        let (&tag, rest) = data.split_first()?;
        Some(match tag {
            0 => {
                // Initialize: guardian, agent, then guard/max/programs
                let guardian = key(rest, 0)?;
                let agent = key(rest, 32)?;
                // Reassemble as a policy: guardian | guard | max | n | programs
                let mut tail = Vec::with_capacity(rest.len() - 32);
                tail.extend_from_slice(&guardian);
                tail.extend_from_slice(rest.get(64..)?);
                VaultInstruction::Initialize { agent, policy: policy_at(&tail, 0)? }
            }
            1 if rest.len() == 8 => VaultInstruction::TransferSol { lamports: u64_at(rest, 0)? },
            2 => VaultInstruction::Execute { data: rest.to_vec() },
            3 if rest.is_empty() => VaultInstruction::Kill,
            4 if rest.is_empty() => VaultInstruction::Revive,
            5 => VaultInstruction::SetPolicy { policy: policy_at(rest, 0)? },
            6 if rest.len() == 8 => VaultInstruction::Withdraw { lamports: u64_at(rest, 0)? },
            7 => VaultInstruction::OwnerExecute { data: rest.to_vec() },
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_bytes(p: &Policy) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&p.guardian);
        v.extend_from_slice(&p.guard_cosigner);
        v.extend_from_slice(&p.max_lamports_per_tx.to_le_bytes());
        v.push(p.allowed_programs.len() as u8);
        for k in &p.allowed_programs {
            v.extend_from_slice(k);
        }
        v
    }

    fn policy() -> Policy {
        Policy { guardian: [2; 32], guard_cosigner: [4; 32], max_lamports_per_tx: 9, allowed_programs: vec![[7; 32]] }
    }

    #[test]
    fn initialize_round_trip() {
        let p = policy();
        let mut data = vec![0u8];
        data.extend_from_slice(&p.guardian);
        data.extend_from_slice(&[3; 32]); // agent
        data.extend_from_slice(&policy_bytes(&p)[32..]);
        assert_eq!(VaultInstruction::unpack(&data), Some(VaultInstruction::Initialize { agent: [3; 32], policy: p }));
    }

    #[test]
    fn set_policy_and_simple_tags() {
        let p = policy();
        let mut data = vec![5u8];
        data.extend_from_slice(&policy_bytes(&p));
        assert_eq!(VaultInstruction::unpack(&data), Some(VaultInstruction::SetPolicy { policy: p }));
        assert_eq!(VaultInstruction::unpack(&[3]), Some(VaultInstruction::Kill));
        assert_eq!(VaultInstruction::unpack(&[4]), Some(VaultInstruction::Revive));
        let mut t = vec![1u8];
        t.extend_from_slice(&42u64.to_le_bytes());
        assert_eq!(VaultInstruction::unpack(&t), Some(VaultInstruction::TransferSol { lamports: 42 }));
    }

    #[test]
    fn malformed_is_none() {
        assert_eq!(VaultInstruction::unpack(&[]), None);
        assert_eq!(VaultInstruction::unpack(&[9]), None);
        assert_eq!(VaultInstruction::unpack(&[3, 0]), None); // trailing bytes on Kill
        assert_eq!(VaultInstruction::unpack(&[1, 1, 2]), None); // short lamports
        let mut too_many = vec![5u8];
        too_many.extend_from_slice(&[0; 72]);
        too_many.push(9); // 9 > MAX_PROGRAMS
        assert_eq!(VaultInstruction::unpack(&too_many), None);
    }
}
