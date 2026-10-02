"""
HYPERION SOLANA GUARD: BUILDING AND SIGNING LEGACY TRANSACTIONS
===============================================================
Enough of Solana's wire format to build the transactions the Guard and the
vault expect, without an SDK: compile instructions into a legacy message,
sign it with any number of Ed25519 keys, and serialize.

Account order follows Solana's rules: the fee payer first, then writable
signers, read-only signers, writable non-signers, read-only non-signers.
Program ids are read-only non-signers.
"""

from __future__ import annotations

from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

from .base58 import b58decode, b58encode
from .vault import Ix


def compact_u16(n: int) -> bytes:
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def compile_message(instructions: list[Ix], fee_payer: str, recent_blockhash: str) -> tuple[bytes, list[str], int]:
    """(message bytes, account keys in order, number of required signers)."""
    flags: dict[str, list[bool]] = {fee_payer: [True, True]}          # key -> [signer, writable]
    order = [fee_payer]
    for ix in instructions:
        for a in ix.accounts:
            if a.pubkey not in flags:
                flags[a.pubkey] = [False, False]
                order.append(a.pubkey)
            flags[a.pubkey][0] |= a.is_signer
            flags[a.pubkey][1] |= a.is_writable
        if ix.program_id not in flags:
            flags[ix.program_id] = [False, False]
            order.append(ix.program_id)

    def rank(k: str) -> int:
        signer, writable = flags[k]
        if k == fee_payer:
            return -1
        return {(True, True): 0, (True, False): 1, (False, True): 2, (False, False): 3}[(signer, writable)]

    keys = sorted(order, key=lambda k: (rank(k), order.index(k)))
    n_signers = sum(flags[k][0] for k in keys)
    ro_signed = sum(1 for k in keys if flags[k][0] and not flags[k][1])
    ro_unsigned = sum(1 for k in keys if not flags[k][0] and not flags[k][1])
    index = {k: i for i, k in enumerate(keys)}

    msg = bytearray([n_signers, ro_signed, ro_unsigned])
    msg += compact_u16(len(keys)) + b"".join(b58decode(k) for k in keys)
    msg += b58decode(recent_blockhash)
    msg += compact_u16(len(instructions))
    for ix in instructions:
        msg.append(index[ix.program_id])
        msg += compact_u16(len(ix.accounts)) + bytes(index[a.pubkey] for a in ix.accounts)
        msg += compact_u16(len(ix.data)) + ix.data
    return bytes(msg), keys, n_signers


def sign(message: bytes, key: ECC.EccKey) -> bytes:
    return eddsa.new(key, "rfc8032").sign(message)


def pubkey(key: ECC.EccKey) -> str:
    return b58encode(key.public_key().export_key(format="raw"))


def serialize(message: bytes, keys: list[str], n_signers: int, signatures: dict[str, bytes]) -> bytes:
    """The wire transaction. Signers without a signature yet get zeros, so a
    partly signed transaction can be passed to the Guard to add its own."""
    sigs = b"".join(signatures.get(k, bytes(64)) for k in keys[:n_signers])
    return compact_u16(n_signers) + sigs + message


def add_signature(raw_tx: bytes, signer: str, signature: bytes) -> bytes:
    """Put `signature` in `signer`'s slot of a serialized transaction."""
    from .decoder import decode_solana_transaction, read_compact_u16
    decoded = decode_solana_transaction(raw_tx)
    slot = decoded.account_keys.index(signer)
    if slot >= decoded.num_required_signatures:
        raise ValueError(f"{signer} isn't a required signer of this transaction")
    _, offset = read_compact_u16(raw_tx, 0)
    at = offset + 64 * slot
    return raw_tx[:at] + signature + raw_tx[at + 64:]
