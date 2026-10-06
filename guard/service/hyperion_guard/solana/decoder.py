"""
HYPERION SOLANA GUARD: TRANSACTION & INSTRUCTION DECODER
=========================================================
Decodes serialized Solana transactions (legacy and VersionedTransaction/v0),
extracts instructions, and deep-inspects operations targeting major Solana venues:
  - Jupiter Aggregator V6 (JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4)
  - Phoenix LOB DEX (PhoeNiXZ8ByJGLkxNfZRnkUfjvmuYqLR89jjFHGqdXY)
  - Raydium AMM V4 (675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8)
  - SPL Token Program (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)
  - System Program (11111111111111111111111111111111)
  - Compute Budget and Associated Token Account, which most real swaps include

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
COMPUTE_BUDGET_PROGRAM_ID = "ComputeBudget111111111111111111111111111111"
ASSOCIATED_TOKEN_PROGRAM_ID = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"

WSOL_MINT = "So11111111111111111111111111111111111111112"
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
USDT_MINT = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"

# Stands in for an account a v0 transaction loads from an address lookup table.
# The table's contents aren't in the transaction, so the address isn't known
# here; the placeholder keeps every other account at its real position.
UNRESOLVED_ACCOUNT = "<address-lookup-table>"

TOKEN_ACCOUNT_RENT_LAMPORTS = 2_039_280      # rent-exempt minimum for a 165-byte token account
MAX_COMPUTE_UNITS = 1_400_000

ALLOWLISTED_PROGRAMS = {
    JUPITER_V6_PROGRAM_ID: "Jupiter V6 Aggregator",
    PHOENIX_PROGRAM_ID: "Phoenix LOB",
    RAYDIUM_V4_PROGRAM_ID: "Raydium AMM V4",
    SPL_TOKEN_PROGRAM_ID: "SPL Token",
    SYSTEM_PROGRAM_ID: "Solana System Program",
    COMPUTE_BUDGET_PROGRAM_ID: "Compute Budget",
    ASSOCIATED_TOKEN_PROGRAM_ID: "Associated Token Account",
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
# Jupiter V6 swap instructions, from the program's on-chain Anchor IDL
# (discriminator = sha256("global:<name>")[:8]). For each: its name, where the
# fixed fields sit, whether the first amount is the exact output, and the
# position of source_mint among the accounts (None where the instruction
# doesn't carry it).
#
#   "tail":   route plan first, then  amount u64, quoted u64, slippage_bps u16, platform_fee_bps u8
#   "ledger": route plan first, then  quoted_out u64, slippage_bps u16, platform_fee_bps u8.
#             The input comes from a token ledger account, so it can't be sized.
#   "head":   [id u8 for the shared forms] amount u64, quoted u64, slippage_bps u16,
#             platform_fee_bps u16, positive_slippage_bps u16, then the route plan
JUPITER_ROUTES: dict[str, tuple[str, str, bool, int | None]] = {
    "e517cb977ae3ad2a": ("route", "tail", False, None),
    "c1209b3341d69c81": ("sharedAccountsRoute", "tail", False, 7),
    "d033ef977b2bed5c": ("exactOutRoute", "tail", True, 5),
    "b0d169a89a7d453e": ("sharedAccountsExactOutRoute", "tail", True, 7),
    "96564774a75d0e68": ("routeWithTokenLedger", "ledger", False, None),
    "e6798f50779f6aaa": ("sharedAccountsRouteWithTokenLedger", "ledger", False, 7),
    "bb64facc31c4af14": ("routeV2", "head", False, 3),
    "9d8ab85215f4f324": ("exactOutRouteV2", "head", True, 3),
    "d19853937cfed8e9": ("sharedAccountsRouteV2", "head", False, 6),
    "3560e5cad8bbfa18": ("sharedAccountsExactOutRouteV2", "head", True, 6),
}
JUPITER_DISCRIMINATORS: dict[str, str] = {disc: route[0] for disc, route in JUPITER_ROUTES.items()}


def decode_jupiter_instruction(data: bytes, accounts: list[str]) -> tuple[str, int | None, int | None, int | None, dict[str, Any]]:
    """
    Decodes Jupiter V6 swaps (see JUPITER_ROUTES for the layouts).

    Returns the most the swap can spend as the input amount: in_amount for an
    exact-in route, and quoted_in_amount plus the slippage allowance for an
    exact-out route. The token-ledger routes take their input from an account,
    not the instruction, so they come back as JUPITER_LEDGER_SWAP with no
    amount, which the Guard refuses.
    """
    discriminator = data[:8].hex()
    route = JUPITER_ROUTES.get(discriminator)
    if route is None:
        return "UNKNOWN_JUPITER", None, None, None, {"discriminator": discriminator, "error": f"unrecognized Jupiter discriminator {discriminator}"}
    route_name, layout, exact_out, mint_at = route
    details: dict[str, Any] = {"instruction_name": route_name, "discriminator": discriminator}
    if mint_at is not None and mint_at < len(accounts) and accounts[mint_at] != UNRESOLVED_ACCOUNT:
        details["source_mint"] = accounts[mint_at]

    try:
        if layout == "ledger":
            if len(data) < 8 + 4 + 11:
                raise struct.error("instruction too short")
            quoted_out, slippage_bps, platform_fee_bps = struct.unpack_from("<QHB", data, len(data) - 11)
            details.update({"quoted_out_raw": quoted_out, "slippage_bps": slippage_bps, "platform_fee_bps": platform_fee_bps})
            return "JUPITER_LEDGER_SWAP", None, quoted_out, slippage_bps, details
        if layout == "tail":
            if len(data) < 8 + 4 + 19:
                raise struct.error("instruction too short")
            val1, val2, slippage_bps, platform_fee_bps = struct.unpack_from("<QQHB", data, len(data) - 19)
            details["route_plan_bytes_len"] = len(data) - 27 - ("shared" in route_name)
        else:
            at = 8 + ("shared" in route_name)
            val1, val2, slippage_bps, platform_fee_bps, positive_slippage_bps, steps = struct.unpack_from("<QQHHHI", data, at)
            details.update({"positive_slippage_bps": positive_slippage_bps, "route_plan_steps": steps})
    except struct.error as exc:
        return "UNKNOWN_JUPITER", None, None, None, {**details, "error": f"malformed {route_name}: {exc}"}

    if exact_out:
        # amount is the exact output; the input is a quote the swap may exceed by the slippage
        out_amount, quoted_in = val1, val2
        in_amount = -(-quoted_in * (10_000 + slippage_bps) // 10_000)
        details.update({"exact": "out", "out_amount_raw": out_amount, "quoted_in_raw": quoted_in, "in_amount_raw": in_amount})
    else:
        in_amount, out_amount = val1, val2
        details.update({"exact": "in", "in_amount_raw": in_amount, "quoted_out_raw": out_amount})
    details.update({"slippage_bps": slippage_bps, "platform_fee_bps": platform_fee_bps})
    return "JUPITER_SWAP", in_amount, out_amount, slippage_bps, details


PHOENIX_INSTRUCTIONS = {
    0: "Swap", 1: "SwapWithFreeFunds", 2: "PlaceLimitOrder", 3: "PlaceLimitOrderWithFreeFunds", 4: "ReduceOrder",
    5: "ReduceOrderWithFreeFunds", 6: "CancelAllOrders", 7: "CancelAllOrdersWithFreeFunds", 8: "CancelUpTo",
    9: "CancelUpToWithFreeFunds", 10: "CancelMultipleOrdersById", 11: "CancelMultipleOrdersByIdWithFreeFunds",
    12: "WithdrawFunds", 13: "DepositFunds", 14: "RequestSeat", 15: "Log", 16: "PlaceMultiplePostOnlyOrders",
    17: "PlaceMultiplePostOnlyOrdersWithFreeFunds",
}
PHOENIX_PACKETS = {0: "PostOnly", 1: "Limit", 2: "ImmediateOrCancel"}


def decode_phoenix_instruction(data: bytes, accounts: list[str]) -> tuple[str, int | None, int | None, int | None, dict[str, Any]]:
    """
    Decodes Phoenix orders (phoenix-v1: program/instruction.rs and
    state/order_schema/order_packet.rs).

      - 1 byte: instruction. 0 Swap, 1 SwapWithFreeFunds, 2 PlaceLimitOrder,
        3 PlaceLimitOrderWithFreeFunds carry a Borsh OrderPacket
      - OrderPacket: 1 byte variant (0 PostOnly, 1 Limit, 2 ImmediateOrCancel),
        1 byte side (0 bid, 1 ask), then
          PostOnly, Limit:    price_in_ticks u64, num_base_lots u64, ...
          ImmediateOrCancel:  price_in_ticks Option<u64>, num_base_lots u64,
                              num_quote_lots u64, min_base_lots_to_fill u64,
                              min_quote_lots_to_fill u64, ...

    Phoenix sizes orders in lots and ticks, and what a lot is worth is set in
    each market's header, which isn't in the transaction. So the Guard can
    read an order but can't put a dollar figure on it, and no amount is
    returned: these are PHOENIX_ORDER, which the Guard refuses until it has
    market parameters. Everything else is named and refused too.
    """
    if not data:
        return "UNKNOWN_PHOENIX", None, None, None, {"error": "empty Phoenix instruction"}
    tag = data[0]
    name = PHOENIX_INSTRUCTIONS.get(tag)
    if name is None:
        return "UNKNOWN_PHOENIX", None, None, None, {"phoenix_tag": tag, "error": f"unrecognized Phoenix instruction {tag}"}
    details: dict[str, Any] = {"instruction_name": name, "phoenix_tag": tag}
    if tag > 3:
        return "PHOENIX_OPERATION", None, None, None, details
    try:
        variant, side = data[1], data[2]
        if variant not in PHOENIX_PACKETS or side > 1:
            raise ValueError(f"order packet variant {variant}, side {side}")
        details.update({"order_type": PHOENIX_PACKETS[variant], "side": "BID" if side == 0 else "ASK"})
        at = 3
        if variant == 2:
            has_price = data[at]
            if has_price > 1:
                raise ValueError(f"Option tag {has_price}")
            at += 1
            details["price_in_ticks"] = struct.unpack_from("<Q", data, at)[0] if has_price else None
            at += 8 * has_price
            (details["num_base_lots"], details["num_quote_lots"], details["min_base_lots_to_fill"],
             details["min_quote_lots_to_fill"]) = struct.unpack_from("<QQQQ", data, at)
        else:
            details["price_in_ticks"], details["num_base_lots"] = struct.unpack_from("<QQ", data, at)
    except (IndexError, struct.error, ValueError) as exc:
        return "UNKNOWN_PHOENIX", None, None, None, {**details, "error": f"malformed order packet: {exc}"}
    return "PHOENIX_ORDER", None, None, None, details


RAYDIUM_SWAPS = {9: "swapBaseIn", 11: "swapBaseOut", 16: "swapBaseInV2", 17: "swapBaseOutV2"}


def decode_raydium_instruction(data: bytes, accounts: list[str]) -> tuple[str, int | None, int | None, int | None, dict[str, Any]]:
    """
    Decodes Raydium AMM V4 swaps (raydium-amm, program/src/instruction.rs).

      - 1 byte: tag. 9 swapBaseIn, 11 swapBaseOut, 16 and 17 their V2 forms
      - swapBaseIn:  amount_in u64, minimum_amount_out u64
      - swapBaseOut: max_amount_in u64, amount_out u64

    The instruction carries no slippage figure, only the limit on the other
    side, so the bps collar can't apply. What can be checked is that there is
    a limit at all: `unbounded` is set when minimum_amount_out is 0 (base-in)
    or max_amount_in is u64::MAX (base-out).

    Everything else Raydium offers (deposit, withdraw, pool admin) is
    UNKNOWN_RAYDIUM, which the Guard refuses.
    """
    if not data or data[0] not in RAYDIUM_SWAPS:
        tag = data[0] if data else None
        return "UNKNOWN_RAYDIUM", None, None, None, {"raydium_tag": tag, "error": f"Raydium instruction {tag} is not a swap"}
    name = RAYDIUM_SWAPS[data[0]]
    if len(data) != 17:
        return "UNKNOWN_RAYDIUM", None, None, None, {"error": f"{name} must be 17 bytes, got {len(data)}"}
    first, second = struct.unpack_from("<QQ", data, 1)
    if "BaseIn" in name:
        in_amount, out_amount, unbounded = first, second, second == 0
    else:
        in_amount, out_amount, unbounded = first, second, first == 0xFFFF_FFFF_FFFF_FFFF
    details: dict[str, Any] = {"instruction_name": name, "in_amount_raw": in_amount, "out_amount_raw": out_amount,
                               "exact": "in" if "BaseIn" in name else "out", "unbounded": unbounded}
    return "RAYDIUM_SWAP", in_amount, out_amount, None, details


SPL_TOKEN_INSTRUCTIONS = {
    0: "InitializeMint", 1: "InitializeAccount", 2: "InitializeMultisig", 3: "Transfer", 4: "Approve", 5: "Revoke",
    6: "SetAuthority", 7: "MintTo", 8: "Burn", 9: "CloseAccount", 10: "FreezeAccount", 11: "ThawAccount",
    12: "TransferChecked", 13: "ApproveChecked", 14: "MintToChecked", 15: "BurnChecked", 16: "InitializeAccount2",
    17: "SyncNative", 18: "InitializeAccount3",
}
# Move nothing and grant nothing: opening a token account, syncing a wrapped-SOL
# balance, taking a delegate's allowance away.
SPL_TOKEN_HARMLESS = {1, 16, 18, 17, 5}


def decode_spl_token_instruction(data: bytes, accounts: list[str]) -> tuple[str, int | None, int | None, int | None, dict[str, Any]]:
    """Decodes SPL Token instructions. Transfers are sized; a few that move
    and grant nothing are TOKEN_HARMLESS; the rest (Approve, SetAuthority,
    CloseAccount to someone else, Burn, ...) are TOKEN_PROGRAM_INSTRUCTION, which the Guard refuses."""
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

    name = SPL_TOKEN_INSTRUCTIONS.get(ins_type, f"instruction {ins_type}")
    # CloseAccount [account, destination, authority]: the account's lamports (all of a
    # wrapped-SOL account's balance) go to `destination`. Harmless only when that is the
    # authority itself, which is how a swap unwraps SOL back to the wallet.
    if ins_type == 9 and len(accounts) >= 3 and accounts[1] == accounts[2] != UNRESOLVED_ACCOUNT:
        return "TOKEN_HARMLESS", None, None, None, {"type": "CloseAccount (to its own authority)", "type_id": ins_type}
    if ins_type in SPL_TOKEN_HARMLESS:
        return "TOKEN_HARMLESS", None, None, None, {"type": name, "type_id": ins_type}
    return "TOKEN_PROGRAM_INSTRUCTION", None, None, None, {"type": name, "type_id": ins_type}


SYSTEM_INSTRUCTIONS = {
    0: "CreateAccount", 1: "Assign", 2: "Transfer", 3: "CreateAccountWithSeed", 4: "AdvanceNonceAccount",
    5: "WithdrawNonceAccount", 6: "InitializeNonceAccount", 7: "AuthorizeNonceAccount", 8: "Allocate",
    9: "AllocateWithSeed", 10: "AssignWithSeed", 11: "TransferWithSeed", 12: "UpgradeNonceAccount",
}


def decode_system_instruction(data: bytes, accounts: list[str]) -> tuple[str, int | None, int | None, int | None, dict[str, Any]]:
    """Decodes System Program instructions. Transfer and CreateAccount both
    move lamports out of the payer and are sized as SOL. The rest is
    SYSTEM_INSTRUCTION, which the Guard refuses: among them
    AdvanceNonceAccount, because a transaction on a durable nonce never
    expires, so a co-signature on one would outlive a kill."""
    ins_type = struct.unpack_from("<I", data, 0)[0] if len(data) >= 4 else None
    if ins_type in (0, 2) and len(data) >= 12:
        lamports = struct.unpack_from("<Q", data, 4)[0]
        return "SOL_TRANSFER", lamports, None, None, {"type": SYSTEM_INSTRUCTIONS[ins_type], "lamports": lamports}

    return "SYSTEM_INSTRUCTION", None, None, None, {"type": SYSTEM_INSTRUCTIONS.get(ins_type, f"instruction {ins_type}")}

def decode_compute_budget_instruction(data: bytes, accounts: list[str]) -> tuple[str, int | None, int | None, int | None, dict[str, Any]]:
    """Compute Budget: 1 RequestHeapFrame u32, 2 SetComputeUnitLimit u32,
    3 SetComputeUnitPrice u64 (micro-lamports per unit), 4
    SetLoadedAccountsDataSizeLimit u32. The price times the limit is the
    priority fee, which the Guard counts as SOL spent."""
    try:
        tag = data[0]
        if tag == 2 and len(data) == 5:
            return "COMPUTE_BUDGET", None, None, None, {"type": "SetComputeUnitLimit", "units": struct.unpack_from("<I", data, 1)[0]}
        if tag == 3 and len(data) == 9:
            return "COMPUTE_BUDGET", None, None, None, {"type": "SetComputeUnitPrice",
                                                        "micro_lamports_per_unit": struct.unpack_from("<Q", data, 1)[0]}
        if tag in (1, 4) and len(data) == 5:
            return "COMPUTE_BUDGET", None, None, None, {"type": "RequestHeapFrame" if tag == 1 else "SetLoadedAccountsDataSizeLimit"}
    except IndexError:
        pass
    return "UNKNOWN_COMPUTE_BUDGET", None, None, None, {"error": "unrecognized Compute Budget instruction"}


def decode_associated_token_instruction(data: bytes, accounts: list[str]) -> tuple[str, int | None, int | None, int | None, dict[str, Any]]:
    """Associated Token Account: Create (no data, or 0) and CreateIdempotent (1)
    open a token account, paid for by the funder: the rent is returned as the
    amount, in lamports. RecoverNested (2) moves tokens and is refused."""
    tag = data[0] if data else 0
    if len(data) <= 1 and tag in (0, 1):
        return "ATA_CREATE", TOKEN_ACCOUNT_RENT_LAMPORTS, None, None, {"type": "CreateIdempotent" if tag else "Create",
                                                                       "lamports": TOKEN_ACCOUNT_RENT_LAMPORTS}
    return "ATA_OPERATION", None, None, None, {"type": "RecoverNested" if tag == 2 else f"instruction {tag}"}


def program_label(prog_id: str) -> str:
    from .vault import VAULT_PROGRAM_IDS
    if prog_id in VAULT_PROGRAM_IDS:
        return "Hyperion Guarded Vault"
    return ALLOWLISTED_PROGRAMS.get(prog_id, "Unknown External Program")


def decode_instruction_for_program(prog_id: str, inst_data: bytes, inst_accounts: list[str]):
    """Decode one instruction for whichever program it targets. Used for
    top-level instructions and for the call inside a vault Execute."""
    from .vault import VAULT_PROGRAM_IDS, decode_vault_instruction
    if prog_id == JUPITER_V6_PROGRAM_ID:
        return decode_jupiter_instruction(inst_data, inst_accounts)
    if prog_id == PHOENIX_PROGRAM_ID:
        return decode_phoenix_instruction(inst_data, inst_accounts)
    if prog_id == RAYDIUM_V4_PROGRAM_ID:
        return decode_raydium_instruction(inst_data, inst_accounts)
    if prog_id == SPL_TOKEN_PROGRAM_ID:
        return decode_spl_token_instruction(inst_data, inst_accounts)
    if prog_id == SYSTEM_PROGRAM_ID:
        return decode_system_instruction(inst_data, inst_accounts)
    if prog_id == COMPUTE_BUDGET_PROGRAM_ID:
        return decode_compute_budget_instruction(inst_data, inst_accounts)
    if prog_id == ASSOCIATED_TOKEN_PROGRAM_ID:
        return decode_associated_token_instruction(inst_data, inst_accounts)
    if prog_id in VAULT_PROGRAM_IDS:
        return decode_vault_instruction(inst_data, inst_accounts)
    return "EXTERNAL_CALL", None, None, None, {"data_len": len(inst_data)}


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
        prog_id = account_keys[prog_id_idx] if prog_id_idx < len(account_keys) else UNRESOLVED_ACCOUNT

        num_acc_idx, msg_offset = read_compact_u16(message_bytes, msg_offset)
        inst_accounts = []
        for _ in range(num_acc_idx):
            acc_idx = message_bytes[msg_offset]
            msg_offset += 1
            # keep positions: an account from a lookup table is a placeholder, not a gap
            inst_accounts.append(account_keys[acc_idx] if acc_idx < len(account_keys) else UNRESOLVED_ACCOUNT)

        data_len, msg_offset = read_compact_u16(message_bytes, msg_offset)
        inst_data = message_bytes[msg_offset:msg_offset+data_len]
        msg_offset += data_len

        # Program-specific decoding
        prog_label = program_label(prog_id)
        op, in_amt, min_out, slip, det = decode_instruction_for_program(prog_id, inst_data, inst_accounts)

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
