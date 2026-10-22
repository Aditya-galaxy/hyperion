"""Write tests/fixtures/hyperliquid_vectors.json with Hyperliquid's own Python SDK.

tests/test_hyperliquid_signing.py checks hyperion_guard.hyperliquid.signing
against this file, so the Guard signs exactly what Hyperliquid checks. Rerun
it only to move to a newer SDK:

    python -m venv /tmp/hl && /tmp/hl/bin/pip install hyperliquid-python-sdk==0.24.0
    /tmp/hl/bin/python tests/fixtures/make_hyperliquid_vectors.py
"""

import json
from pathlib import Path

from eth_account import Account
from hyperliquid.utils.signing import (
    CONVERT_TO_MULTI_SIG_USER_SIGN_TYPES,
    WITHDRAW_SIGN_TYPES,
    action_hash,
    sign_convert_to_multi_sig_user_action,
    sign_l1_action,
    sign_multi_sig_action,
    sign_multi_sig_l1_action_payload,
    sign_multi_sig_user_signed_action_payload,
)

KEYS = {name: "0x" + bytes([i + 1]).hex() * 32 for i, name in enumerate(["account", "agent", "guard", "owner"])}
ADDR = {name: Account.from_key(key).address for name, key in KEYS.items()}
NONCE = 1_760_000_000_000
EXPIRES = NONCE + 60_000

ORDER = {"type": "order", "orders": [{"a": 3, "b": True, "p": "81000", "s": "0.001", "r": False,
                                      "t": {"limit": {"tif": "Ioc"}}}], "grouping": "na"}
CANCEL = {"type": "cancel", "cancels": [{"a": 3, "o": 123456}]}

out = {"sdk": "hyperliquid-python-sdk==0.24.0", "keys": KEYS, "addresses": ADDR, "nonce": NONCE, "expires_after": EXPIRES,
       "actions": {"order": ORDER, "cancel": CANCEL}, "cases": {}}
for network, is_mainnet in (("mainnet", True), ("testnet", False)):
    for name, action in (("order", ORDER), ("cancel", CANCEL)):
        case = {
            "hash": action_hash(action, None, NONCE, EXPIRES).hex(),
            "hash_no_expiry": action_hash(action, None, NONCE, None).hex(),
            "plain": sign_l1_action(Account.from_key(KEYS["agent"]), action, None, NONCE, EXPIRES, is_mainnet),
            "cosigned": {who: sign_multi_sig_l1_action_payload(Account.from_key(KEYS[who]), action, is_mainnet, None, NONCE,
                                                                EXPIRES, ADDR["account"], ADDR["agent"])
                         for who in ("agent", "guard")},
        }
        multi = {"type": "multiSig", "signatureChainId": "0x66eee",
                 "signatures": [case["cosigned"]["agent"], case["cosigned"]["guard"]],
                 "payload": {"multiSigUser": ADDR["account"].lower(), "outerSigner": ADDR["agent"].lower(), "action": action}}
        case["multi_sig_action"] = multi
        case["outer"] = sign_multi_sig_action(Account.from_key(KEYS["agent"]), multi, is_mainnet, None, NONCE, EXPIRES)
        out["cases"][f"{network}/{name}"] = case
    convert = {"type": "convertToMultiSigUser",
               "signers": json.dumps({"authorizedUsers": sorted([ADDR["owner"], ADDR["agent"], ADDR["guard"]]), "threshold": 2}),
               "nonce": NONCE}
    signature = sign_convert_to_multi_sig_user_action(Account.from_key(KEYS["account"]), convert, is_mainnet)
    out["cases"][f"{network}/convert"] = {"action": convert, "signature": signature}   # the SDK adds the chain fields to it

# user-signed actions on a multi-sig account, as the owner (outer signer) and the Guard sign them
WITHDRAW = {"type": "withdraw3", "signatureChainId": "0x66eee", "hyperliquidChain": "Testnet",
            "destination": ADDR["owner"].lower(), "amount": "25.5", "time": NONCE}
TO_NORMAL = {"type": "convertToMultiSigUser", "signatureChainId": "0x66eee", "hyperliquidChain": "Testnet",
             "signers": "null", "nonce": NONCE}
for network, is_mainnet in (("mainnet", True), ("testnet", False)):
    for name, action, types, primary in (("withdraw", WITHDRAW, WITHDRAW_SIGN_TYPES, "HyperliquidTransaction:Withdraw"),
                                         ("to_normal", TO_NORMAL, CONVERT_TO_MULTI_SIG_USER_SIGN_TYPES,
                                          "HyperliquidTransaction:ConvertToMultiSigUser")):
        posted = dict(action, hyperliquidChain="Mainnet" if is_mainnet else "Testnet")
        out["cases"][f"{network}/{name}"] = {"action": posted, "signatures": {
            who: sign_multi_sig_user_signed_action_payload(Account.from_key(KEYS[who]), dict(posted), is_mainnet, types, primary,
                                                           ADDR["account"], ADDR["owner"])
            for who in ("owner", "guard")}}

Path(__file__).with_name("hyperliquid_vectors.json").write_text(json.dumps(out, indent=1) + "\n")
print("wrote", len(out["cases"]), "cases")
