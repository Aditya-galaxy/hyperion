"""
HYPERION SOLANA GUARD: TRANSACTION & INSTRUCTION DECODER
=========================================================
Decodes serialized Solana transactions (legacy and VersionedTransaction/v0),
extracts instructions, and deep-inspects operations targeting major Solana venues:
  - Jupiter Aggregator V6 (JUP6LkbZbjS1jKKwapdHNy74bHT3TL5K1449dk94Q1v5)
  - Phoenix LOB DEX (PhoeNiXZ8ByJGLkxNfZRnkUfjvmuYqLR89jjFHGqdXY)
  - Raydium AMM V4 (675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8)
  - SPL Token Program (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)
  - System Program (11111111111111111111111111111111)

Extracts input amounts, target venues, and slippage tolerances so the Guard firewall
evaluates real on-chain intent rather than unverified agent declarations.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

from .base58 import b58encode

# Known Solana Program IDs
JUPITER_V6_PROGRAM_ID = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"
PHOENIX_PROGRAM_ID = "PhoeNiXZ8ByJGLkxNfZRnkUfjvmuYqLR89jjFHGqdXY"
RAYDIUM_V4_PROGRAM_ID = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8"
SPL_TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
SYSTEM_PROGRAM_ID = "11111111111111111111111111111111"

ALLOWLISTED_PROGRAMS = {
    JUPITER_V6_PROGRAM_ID: "Jupiter V6 Aggregator",
    PHOENIX_PROGRAM_ID: "Phoenix LOB",
    RAYDIUM_V4_PROGRAM_ID: "Raydium V4",
    SPL_TOKEN_PROGRAM_ID: "SPL Token",
    SYSTEM_PROGRAM_ID: "Solana System Program",
}

@dataclass
class DecodedInstruction:
    program_id: str
    program_label: str
    operation: str
    accounts: list[str]
    input_amount: int | None = None
    min_output_amount: int | None = None
    slippage_bps: int | None = None
    details: dict[str, Any] = field(default_factory=dict)

@dataclass
class DecodedSolanaTransaction:
    message_bytes: bytes
    signatures: list[str]
    account_keys: list[str]
    recent_blockhash: str
    instructions: list[DecodedInstruction]
    is_versioned: bool
    num_required_signatures: int

def read_compact_u16(data: bytes, offset: int) -> tuple[int, int]:
    """Reads a Solana compact-u16 integer and returns (value, new_offset)."""
    val = 0
    shift = 0
    idx = offset
    while True:
        byte = data[idx]
        idx += 1
        val |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
    return val, idx

# Published Jupiter V6 Anchor Instruction Discriminators (sha256("global:<name>")[:8])
JUPITER_DISCRIMINATORS: dict[str, str] = {
    "e517cb977ae3ad2a": "route",
    "5703feb8e7573909": "sharedAccountsRoute",
    "34650f14745e8de8": "routeWithTokenLedger",
    "b4476e37d9cc1af6": "sharedAccountsRouteWithTokenLedger",
    "7e2c8ea1d9a65bc6": "exactOutRoute",
    "41d8fa8dac726b69": "sharedAccountsExactOutRoute",
}


def decode_jupiter_instruction(data: bytes, accounts: list[str]) -> tuple[str, int | None, int | None, int | None, dict[str, Any]]:
    """
    Decodes Jupiter V6 Aggregator instructions.

    Jupiter V6 published IDL layout:
      - 8 bytes: Anchor discriminator (e.g. e517cb977ae3ad2a for route, 5703feb8e7573909 for sharedAccountsRoute)
      - Variable length: routePlan: Vec<RoutePlanStep> (precedes the fixed fields)
      - Exactly 19 bytes at the END of the instruction:
          - inAmount: u64 (8 bytes, little-endian)
          - quotedOutAmount: u64 (8 bytes, little-endian)
          - slippageBps: u16 (2 bytes, little-endian)
          - platformFeeBps: u8 (1 byte)
    """
    if len(data) < 27:
        return "UNKNOWN_JUPITER", None, None, None, {"error": "instruction too short (< 27 bytes for Jupiter route)"}

    discriminator = data[:8].hex()
    route_name = JUPITER_DISCRIMINATORS.get(discriminator)
    if not route_name:
        return "UNKNOWN_JUPITER", None, None, None, {"discriminator": discriminator, "error": f"unrecognized Jupiter discriminator {discriminator}"}

    try:
        in_amount, quoted_out, slippage_bps, platform_fee_bps = struct.unpack_from("<QQHB", data, len(data) - 19)
    except struct.error as exc:
        return "UNKNOWN_JUPITER", None, None, None, {"discriminator": discriminator, "error": str(exc)}

    details: dict[str, Any] = {
        "instruction_name": route_name,
        "discriminator": discriminator,
        "in_amount_raw": in_amount,
        "quoted_out_raw": quoted_out,
        "slippage_bps": slippage_bps,
        "platform_fee_bps": platform_fee_bps,
        "route_plan_bytes_len": len(data) - 27,
    }

    return "JUPITER_SWAP", in_amount, quoted_out, slippage_bps, details

def decode_phoenix_instruction(data: bytes, accounts: list[str]) -> tuple[str, int | None, int | None, int | None, dict[str, Any]]:
    """Decodes Phoenix Limit Order Book instructions."""
    if len(data) < 1:
        return "UNKNOWN_PHOENIX", None, None, None, {}

    tag = data[0]
    details: dict[str, Any] = {"phoenix_tag": tag}

    # Tag 0 = Swap / Market Order, Tag 1 = NewOrder / Limit Order
    if tag == 0 and len(data) >= 9:
        amount = struct.unpack_from("<Q", data, 1)[0]
        return "PHOENIX_SWAP", amount, None, None, details
    elif tag == 1 and len(data) >= 18:
        side = data[1] # 0 = Bid, 1 = Ask
        price_ticks = struct.unpack_from("<Q", data, 2)[0]
        lots = struct.unpack_from("<Q", data, 10)[0]
        details.update({"side": "BID" if side == 0 else "ASK", "price_ticks": price_ticks, "lots": lots})
        return "PHOENIX_LIMIT_ORDER", lots, None, None, details

    return "PHOENIX_OPERATION", None, None, None, details

def decode_spl_token_instruction(data: bytes, accounts: list[str]) -> tuple[str, int | None, int | None, int | None, dict[str, Any]]:
    """Decodes SPL Token Program transfers."""
    if len(data) < 1:
        return "UNKNOWN_TOKEN", None, None, None, {}

    ins_type = data[0]
    if ins_type == 3 and len(data) >= 9: # Transfer
        amount = struct.unpack_from("<Q", data, 1)[0]
        return "TOKEN_TRANSFER", amount, None, None, {"type": "Transfer", "amount": amount}
    elif ins_type == 12 and len(data) >= 10: # TransferChecked
        amount = struct.unpack_from("<Q", data, 1)[0]
        decimals = data[9]
        return "TOKEN_TRANSFER_CHECKED", amount, None, None, {"type": "TransferChecked", "amount": amount, "decimals": decimals}

    return "TOKEN_PROGRAM_INSTRUCTION", None, None, None, {"type_id": ins_type}

def decode_system_instruction(data: bytes, accounts: list[str]) -> tuple[str, int | None, int | None, int | None, dict[str, Any]]:
    """Decodes Solana System Program instructions (SOL transfers)."""
    if len(data) >= 12:
        ins_type = struct.unpack_from("<I", data, 0)[0]
        if ins_type == 2: # Transfer
            lamports = struct.unpack_from("<Q", data, 4)[0]
            return "SOL_TRANSFER", lamports, None, None, {"lamports": lamports}

    return "SYSTEM_INSTRUCTION", None, None, None, {}

def decode_solana_transaction(raw_bytes: bytes) -> DecodedSolanaTransaction:
    """
    Parses a wire-format Solana transaction (Legacy or Versioned v0).
    Extracts the message, signatures, accounts, and decoded instructions.
    """
    if len(raw_bytes) < 65:
        raise ValueError("Transaction payload too short to be a valid Solana transaction")

    offset = 0
    # 1. Read signatures list (compact-u16 length + 64 bytes per sig)
    num_sigs, offset = read_compact_u16(raw_bytes, offset)
    signatures = []
    for _ in range(num_sigs):
        sig = raw_bytes[offset:offset+64]
        offset += 64
        signatures.append(b58encode(sig))

    # The remainder is the serialized Message
    message_bytes = raw_bytes[offset:]
    msg_offset = 0

    # 2. Inspect version prefix (0x80 indicates Versioned Transaction v0)
    first_byte = message_bytes[msg_offset]
    is_versioned = bool(first_byte & 0x80)
    if is_versioned:
        msg_offset += 1 # Skip version byte

    # 3. Message Header (3 bytes: num_required_signatures, num_readonly_signed, num_readonly_unsigned)
    num_required_signatures = message_bytes[msg_offset]
    msg_offset += 3

    # 4. Account Keys
    num_accounts, msg_offset = read_compact_u16(message_bytes, msg_offset)
    account_keys = []
    for _ in range(num_accounts):
        pubkey = message_bytes[msg_offset:msg_offset+32]
        msg_offset += 32
        account_keys.append(b58encode(pubkey))

    # 5. Recent Blockhash (32 bytes)
    blockhash_bytes = message_bytes[msg_offset:msg_offset+32]
    msg_offset += 32
    recent_blockhash = b58encode(blockhash_bytes)

    # 6. Compiled Instructions
    num_instructions, msg_offset = read_compact_u16(message_bytes, msg_offset)
    instructions: list[DecodedInstruction] = []

    for _ in range(num_instructions):
        prog_id_idx = message_bytes[msg_offset]
        msg_offset += 1
        prog_id = account_keys[prog_id_idx] if prog_id_idx < len(account_keys) else "UNKNOWN"

        num_acc_idx, msg_offset = read_compact_u16(message_bytes, msg_offset)
        inst_accounts = []
        for _ in range(num_acc_idx):
            acc_idx = message_bytes[msg_offset]
            msg_offset += 1
            if acc_idx < len(account_keys):
                inst_accounts.append(account_keys[acc_idx])

        data_len, msg_offset = read_compact_u16(message_bytes, msg_offset)
        inst_data = message_bytes[msg_offset:msg_offset+data_len]
        msg_offset += data_len

        # Program-specific decoding
        prog_label = ALLOWLISTED_PROGRAMS.get(prog_id, "Unknown External Program")
        if prog_id == JUPITER_V6_PROGRAM_ID:
            op, in_amt, min_out, slip, det = decode_jupiter_instruction(inst_data, inst_accounts)
        elif prog_id == PHOENIX_PROGRAM_ID:
            op, in_amt, min_out, slip, det = decode_phoenix_instruction(inst_data, inst_accounts)
        elif prog_id == SPL_TOKEN_PROGRAM_ID:
            op, in_amt, min_out, slip, det = decode_spl_token_instruction(inst_data, inst_accounts)
        elif prog_id == SYSTEM_PROGRAM_ID:
            op, in_amt, min_out, slip, det = decode_system_instruction(inst_data, inst_accounts)
        else:
            op, in_amt, min_out, slip, det = "EXTERNAL_CALL", None, None, None, {"data_len": len(inst_data)}

        instructions.append(DecodedInstruction(
            program_id=prog_id,
            program_label=prog_label,
            operation=op,
            accounts=inst_accounts,
            input_amount=in_amt,
            min_output_amount=min_out,
            slippage_bps=slip,
            details=det
        ))

    return DecodedSolanaTransaction(
        message_bytes=message_bytes,
        signatures=signatures,
        account_keys=account_keys,
        recent_blockhash=recent_blockhash,
        instructions=instructions,
        is_versioned=is_versioned,
        num_required_signatures=num_required_signatures,
    )
