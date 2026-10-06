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
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
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

# The tokens the Guard can put a dollar figure on: the two dollar stablecoins
# (6 decimals, taken at $1) and wrapped SOL (9 decimals, at the SOL price).
PRICED_MINTS = (USDC_MINT, USDT_MINT, WSOL_MINT)

# Given a lookup table's address and the highest index a transaction uses in
# it, return the table's addresses in order (or None if it can't be read).
LookupTables = Callable[[str, int], Sequence[str] | None]

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

@lru_cache(maxsize=4096)
def associated_token_address(owner: str, mint: str) -> str:
    """The owner's associated token account for `mint` (classic token program)."""
    from .base58 import b58decode
    from .vault import find_program_address
    return find_program_address([b58decode(owner), b58decode(SPL_TOKEN_PROGRAM_ID), b58decode(mint)],
                                ASSOCIATED_TOKEN_PROGRAM_ID)[0]


def _at(accounts: list[str], i: int | None) -> str | None:
    """The account at position i (negative counts from the end), if it's there and known."""
    if i is None or not -len(accounts) <= i < len(accounts) or accounts[i] == UNRESOLVED_ACCOUNT:
        return None
    return accounts[i]


def source_mint(accounts: list[str], mint_at: int | None, owner_at: int | None, token_account_at: int | None) -> str | None:
    """Which token an instruction spends. Read from the accounts where the
    instruction names its mint; otherwise worked out, for the tokens the Guard
    can price, by checking whether the token account being spent is the
    owner's associated token account for one of them. None if neither works."""
    mint = _at(accounts, mint_at)
    if mint:
        return mint
    owner, token_account = _at(accounts, owner_at), _at(accounts, token_account_at)
    if owner and token_account:
        try:
            for candidate in PRICED_MINTS:
                if associated_token_address(owner, candidate) == token_account:
                    return candidate
        except ValueError:
            return None
    return None


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
    lookup_tables: list[str] = field(default_factory=list)      # address lookup tables a v0 transaction uses
    unresolved_accounts: int = 0                                # accounts from those tables left unknown

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
# fixed fields sit, whether the first amount is the exact output, and where
# among the accounts to find what it spends.
#
#   "tail":   route plan first, then  amount u64, quoted u64, slippage_bps u16, platform_fee_bps u8
#   "ledger": route plan first, then  quoted_out u64, slippage_bps u16, platform_fee_bps u8.
#             The input comes from a token ledger account, so it can't be sized.
#   "head":   [id u8 for the shared forms] amount u64, quoted u64, slippage_bps u16,
#             platform_fee_bps u16, positive_slippage_bps u16, then the route plan
JUPITER_ROUTES: dict[str, tuple[str, str, bool, int | None, int, int]] = {
    # name, layout, exact out, then positions among the accounts of:
    # source_mint (None if not carried), the transfer authority, the token account spent
    "e517cb977ae3ad2a": ("route", "tail", False, None, 1, 2),
    "c1209b3341d69c81": ("sharedAccountsRoute", "tail", False, 7, 2, 3),
    "d033ef977b2bed5c": ("exactOutRoute", "tail", True, 5, 1, 2),
    "b0d169a89a7d453e": ("sharedAccountsExactOutRoute", "tail", True, 7, 2, 3),
    "96564774a75d0e68": ("routeWithTokenLedger", "ledger", False, None, 1, 2),
    "e6798f50779f6aaa": ("sharedAccountsRouteWithTokenLedger", "ledger", False, 7, 2, 3),
    "bb64facc31c4af14": ("routeV2", "head", False, 3, 0, 1),
    "9d8ab85215f4f324": ("exactOutRouteV2", "head", True, 3, 0, 1),
    "d19853937cfed8e9": ("sharedAccountsRouteV2", "head", False, 6, 1, 2),
    "3560e5cad8bbfa18": ("sharedAccountsExactOutRouteV2", "head", True, 6, 1, 2),
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
    route_name, layout, exact_out, mint_at, owner_at, token_account_at = route
    details: dict[str, Any] = {"instruction_name": route_name, "discriminator": discriminator}
    mint = source_mint(accounts, mint_at, owner_at, token_account_at)
    if mint:
        details["source_mint"] = mint

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
    # every swap form ends: user source token account, user destination token account, user owner
    mint = source_mint(accounts, None, -1, -3) if len(accounts) >= 8 else None
    if mint:
        details["source_mint"] = mint
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
        details: dict[str, Any] = {"type": "Transfer", "amount": amount}
        mint = source_mint(accounts, None, 2, 0) if len(accounts) >= 3 else None       # [source, destination, authority]
        if mint:
            details["source_mint"] = mint
        return "TOKEN_TRANSFER", amount, None, None, details
    elif ins_type == 12 and len(data) >= 10: # TransferChecked
        amount = struct.unpack_from("<Q", data, 1)[0]
        decimals = data[9]
        details = {"type": "TransferChecked", "amount": amount, "decimals": decimals}
        mint = source_mint(accounts, 1, 3, 0) if len(accounts) >= 4 else None          # [source, mint, destination, authority]
        if mint:
            details["source_mint"] = mint
        return "TOKEN_TRANSFER_CHECKED", amount, None, None, details

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
        # Transfer [from, to] into the sender's own wrapped-SOL account is a wrap: the
        # SOL is still the sender's, and the swap that spends it is what gets sized.
        sender, to = _at(accounts, 0), _at(accounts, 1)
        if ins_type == 2 and sender and to:
            try:
                if associated_token_address(sender, WSOL_MINT) == to:
                    return "SOL_WRAP", lamports, None, None, {"type": "Transfer (wrap)", "lamports": lamports}
            except ValueError:
                pass
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


def decode_solana_transaction(raw_bytes: bytes, lookup_tables: LookupTables | None = None) -> DecodedSolanaTransaction:
    """
    Parses a wire-format Solana transaction (Legacy or Versioned v0).
    Extracts the message, signatures, accounts, and decoded instructions.

    A v0 transaction names most of its accounts by index into address lookup
    tables. With `lookup_tables` those are resolved; without it, or for a
    table or index it can't supply, the account is UNRESOLVED_ACCOUNT. Program
    ids are never taken from a table, as on-chain.
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

    # 6. Compiled Instructions: program index, account indexes, data
    num_instructions, msg_offset = read_compact_u16(message_bytes, msg_offset)
    compiled: list[tuple[int, list[int], bytes]] = []
    for _ in range(num_instructions):
        prog_id_idx = message_bytes[msg_offset]
        msg_offset += 1
        num_acc_idx, msg_offset = read_compact_u16(message_bytes, msg_offset)
        acc_idxs = list(message_bytes[msg_offset:msg_offset+num_acc_idx])
        msg_offset += num_acc_idx
        data_len, msg_offset = read_compact_u16(message_bytes, msg_offset)
        compiled.append((prog_id_idx, acc_idxs, message_bytes[msg_offset:msg_offset+data_len]))
        msg_offset += data_len

    # 7. Address table lookups (v0). The full account list is the static keys, then
    # every table's writable accounts, then every table's read-only accounts.
    tables: list[str] = []
    loaded_writable: list[str] = []
    loaded_readonly: list[str] = []
    if is_versioned and msg_offset < len(message_bytes):
        num_lookups, msg_offset = read_compact_u16(message_bytes, msg_offset)
        for _ in range(num_lookups):
            table = b58encode(message_bytes[msg_offset:msg_offset+32])
            msg_offset += 32
            n_w, msg_offset = read_compact_u16(message_bytes, msg_offset)
            writable = list(message_bytes[msg_offset:msg_offset+n_w])
            msg_offset += n_w
            n_r, msg_offset = read_compact_u16(message_bytes, msg_offset)
            readonly = list(message_bytes[msg_offset:msg_offset+n_r])
            msg_offset += n_r
            tables.append(table)

            addresses: Sequence[str] | None = None
            if lookup_tables is not None and (writable or readonly):
                try:
                    addresses = lookup_tables(table, max(writable + readonly))
                except (OSError, ValueError, LookupError):      # a table that can't be read leaves its accounts unknown
                    addresses = None

            def pick(i: int, addresses: Sequence[str] | None = addresses) -> str:
                return addresses[i] if addresses is not None and i < len(addresses) else UNRESOLVED_ACCOUNT
            loaded_writable += [pick(i) for i in writable]
            loaded_readonly += [pick(i) for i in readonly]
    all_keys = account_keys + loaded_writable + loaded_readonly

    instructions: list[DecodedInstruction] = []
    for prog_id_idx, acc_idxs, inst_data in compiled:
        prog_id = account_keys[prog_id_idx] if prog_id_idx < len(account_keys) else UNRESOLVED_ACCOUNT
        # keep positions: an account that can't be resolved is a placeholder, not a gap
        inst_accounts = [all_keys[i] if i < len(all_keys) else UNRESOLVED_ACCOUNT for i in acc_idxs]

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
        lookup_tables=tables,
        unresolved_accounts=(loaded_writable + loaded_readonly).count(UNRESOLVED_ACCOUNT),
    )
