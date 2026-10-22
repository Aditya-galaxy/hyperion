"""
HYPERION HYPERLIQUID GUARD: HOW HYPERLIQUID SIGNATURES ARE MADE
===============================================================
Byte for byte what Hyperliquid's Python SDK does (hyperliquid/utils/signing.py,
v0.24.0); tests/test_hyperliquid_signing.py checks it against vectors that SDK
produced.

A trading action ("order", "cancel", ...) is an L1 action. Its signature is
an EIP-712 signature over a "phantom agent" whose connectionId is

    keccak256( msgpack(action) || nonce (8 bytes, big-endian)
               || 0x00 (no vault) || 0x00 || expiresAfter (8 bytes) )

msgpack keeps the action's key order, so the action must be sent to
Hyperliquid exactly as it was signed.

On a multi-sig account each authorized user signs, the same way, the
envelope [multiSigUser, outerSigner, action] instead of the bare action. The
outer signer (the "leader", here the agent) then wraps the action and the
signatures in a "multiSig" action and signs that as a user-signed action
(HyperliquidTransaction:SendMultiSig). Only the leader's nonce is checked.
"""

from __future__ import annotations

from typing import Any

import msgpack
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak, to_hex

SIGNATURE_CHAIN_ID = "0x66eee"       # what the SDK signs with; any chain id works

L1_DOMAIN = {"chainId": 1337, "name": "Exchange", "verifyingContract": "0x0000000000000000000000000000000000000000",
             "version": "1"}
EIP712_DOMAIN = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]
SEND_MULTI_SIG = [
    {"name": "hyperliquidChain", "type": "string"},
    {"name": "multiSigActionHash", "type": "bytes32"},
    {"name": "nonce", "type": "uint64"},
]

Signature = dict[str, Any]           # {"r": "0x…", "s": "0x…", "v": 27 | 28}

_CHAIN = {"name": "hyperliquidChain", "type": "string"}
# Actions that move money or change who controls the account aren't L1 actions: each has its
# own EIP-712 type. The Guard signs these only when the owner asks (see guard.py).
USER_SIGNED: dict[str, tuple[str, list[dict]]] = {
    "usdSend": ("HyperliquidTransaction:UsdSend", [_CHAIN, {"name": "destination", "type": "string"},
                {"name": "amount", "type": "string"}, {"name": "time", "type": "uint64"}]),
    "spotSend": ("HyperliquidTransaction:SpotSend", [_CHAIN, {"name": "destination", "type": "string"},
                 {"name": "token", "type": "string"}, {"name": "amount", "type": "string"}, {"name": "time", "type": "uint64"}]),
    "withdraw3": ("HyperliquidTransaction:Withdraw", [_CHAIN, {"name": "destination", "type": "string"},
                  {"name": "amount", "type": "string"}, {"name": "time", "type": "uint64"}]),
    "usdClassTransfer": ("HyperliquidTransaction:UsdClassTransfer", [_CHAIN, {"name": "amount", "type": "string"},
                         {"name": "toPerp", "type": "bool"}, {"name": "nonce", "type": "uint64"}]),
    "sendAsset": ("HyperliquidTransaction:SendAsset", [_CHAIN, {"name": "destination", "type": "string"},
                  {"name": "sourceDex", "type": "string"}, {"name": "destinationDex", "type": "string"},
                  {"name": "token", "type": "string"}, {"name": "amount", "type": "string"},
                  {"name": "fromSubAccount", "type": "string"}, {"name": "nonce", "type": "uint64"}]),
    "convertToMultiSigUser": ("HyperliquidTransaction:ConvertToMultiSigUser", [_CHAIN, {"name": "signers", "type": "string"},
                              {"name": "nonce", "type": "uint64"}]),
}


def action_hash(action: Any, nonce: int, expires_after: int | None, vault_address: str | None = None) -> bytes:
    data = msgpack.packb(action)
    data += int(nonce).to_bytes(8, "big")
    if vault_address is None:
        data += b"\x00"
    else:
        data += b"\x01" + bytes.fromhex(vault_address.removeprefix("0x"))
    if expires_after is not None:
        data += b"\x00" + int(expires_after).to_bytes(8, "big")
    return keccak(data)


def _l1_typed_data(connection_id: bytes, is_mainnet: bool) -> dict:
    return {
        "domain": L1_DOMAIN,
        "types": {"Agent": [{"name": "source", "type": "string"}, {"name": "connectionId", "type": "bytes32"}],
                  "EIP712Domain": EIP712_DOMAIN},
        "primaryType": "Agent",
        "message": {"source": "a" if is_mainnet else "b", "connectionId": connection_id},
    }


def _user_signed_typed_data(primary_type: str, fields: list[dict], message: dict) -> dict:
    return {
        "domain": {"name": "HyperliquidSignTransaction", "version": "1", "chainId": int(message["signatureChainId"], 16),
                   "verifyingContract": "0x0000000000000000000000000000000000000000"},
        "types": {primary_type: fields, "EIP712Domain": EIP712_DOMAIN},
        "primaryType": primary_type,
        "message": message,
    }


def _sign(key: str | bytes, typed: dict) -> Signature:
    signed = Account.sign_message(encode_typed_data(full_message=typed), key)
    return {"r": to_hex(signed.r), "s": to_hex(signed.s), "v": signed.v}


def _recover(typed: dict, signature: Signature) -> str:
    return Account.recover_message(encode_typed_data(full_message=typed),
                                   vrs=(signature["v"], signature["r"], signature["s"]))


def envelope(multi_sig_user: str, outer_signer: str, action: dict) -> list:
    """What each authorized user of a multi-sig account signs for `action`."""
    return [multi_sig_user.lower(), outer_signer.lower(), action]


def sign_l1(key: str | bytes, action: Any, nonce: int, expires_after: int | None, is_mainnet: bool) -> Signature:
    return _sign(key, _l1_typed_data(action_hash(action, nonce, expires_after), is_mainnet))


def recover_l1(action: Any, nonce: int, expires_after: int | None, is_mainnet: bool, signature: Signature) -> str:
    """The address that made `signature` over `action`, checksummed."""
    return _recover(_l1_typed_data(action_hash(action, nonce, expires_after), is_mainnet), signature)


def multi_sig_action(multi_sig_user: str, outer_signer: str, action: dict, signatures: list[Signature]) -> dict:
    """The action the leader posts to /exchange, carrying every co-signature."""
    return {
        "type": "multiSig",
        "signatureChainId": SIGNATURE_CHAIN_ID,
        "signatures": signatures,
        "payload": {"multiSigUser": multi_sig_user.lower(), "outerSigner": outer_signer.lower(), "action": action},
    }


def sign_multi_sig(key: str | bytes, multi_sig: dict, nonce: int, expires_after: int | None, is_mainnet: bool) -> Signature:
    """The leader's own signature over a multiSig action."""
    without_type = {k: v for k, v in multi_sig.items() if k != "type"}
    message = {"hyperliquidChain": "Mainnet" if is_mainnet else "Testnet",
               "multiSigActionHash": action_hash(without_type, nonce, expires_after), "nonce": nonce,
               "signatureChainId": SIGNATURE_CHAIN_ID}
    return _sign(key, _user_signed_typed_data("HyperliquidTransaction:SendMultiSig", SEND_MULTI_SIG, message))


def sign_user_signed(key: str | bytes, action: dict, is_mainnet: bool) -> Signature:
    """A plain account's own signature over a user-signed action (USER_SIGNED): a transfer, or
    turning it into a multi-sig. As in the SDK, the chain fields are added to `action` itself,
    which is then posted as it is."""
    action.update(signatureChainId=SIGNATURE_CHAIN_ID, hyperliquidChain="Mainnet" if is_mainnet else "Testnet")
    primary, fields = USER_SIGNED[action["type"]]
    return _sign(key, _user_signed_typed_data(primary, fields, action))


def sign_convert_to_multi_sig(key: str | bytes, action: dict, is_mainnet: bool) -> Signature:
    return sign_user_signed(key, action, is_mainnet)


def _multi_sig_user_signed(action: dict, multi_sig_user: str, outer_signer: str, is_mainnet: bool) -> dict:
    primary, fields = USER_SIGNED[action["type"]]
    at = next(i for i, f in enumerate(fields) if f["name"] == "hyperliquidChain") + 1
    fields = fields[:at] + [{"name": "payloadMultiSigUser", "type": "address"},
                            {"name": "outerSigner", "type": "address"}] + fields[at:]
    message = {**action, "payloadMultiSigUser": multi_sig_user.lower(), "outerSigner": outer_signer.lower(),
               "signatureChainId": SIGNATURE_CHAIN_ID, "hyperliquidChain": "Mainnet" if is_mainnet else "Testnet"}
    return _user_signed_typed_data(primary, fields, message)


def sign_multi_sig_user_signed(key: str | bytes, action: dict, multi_sig_user: str, outer_signer: str,
                               is_mainnet: bool) -> Signature:
    """An authorized user's signature over a user-signed action (USER_SIGNED) for a multi-sig account."""
    return _sign(key, _multi_sig_user_signed(action, multi_sig_user, outer_signer, is_mainnet))


def recover_multi_sig_user_signed(action: dict, multi_sig_user: str, outer_signer: str, is_mainnet: bool,
                                  signature: Signature) -> str:
    return _recover(_multi_sig_user_signed(action, multi_sig_user, outer_signer, is_mainnet), signature)
