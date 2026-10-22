"""The Guard's Hyperliquid signing against vectors from Hyperliquid's own SDK
(tests/fixtures/make_hyperliquid_vectors.py). If these pass, Hyperliquid
accepts what the Guard signs."""

import copy
import json
from pathlib import Path

import pytest
from hyperion_guard.hyperliquid import signing

V = json.loads((Path(__file__).parent / "fixtures" / "hyperliquid_vectors.json").read_text())
KEYS, ADDR, NONCE, EXPIRES = V["keys"], V["addresses"], V["nonce"], V["expires_after"]
CASES = [(network, name) for network in ("mainnet", "testnet") for name in ("order", "cancel")]


@pytest.mark.parametrize("network,name", CASES)
def test_action_hash(network, name):
    case, action = V["cases"][f"{network}/{name}"], V["actions"][name]
    assert signing.action_hash(action, NONCE, EXPIRES).hex() == case["hash"]
    assert signing.action_hash(action, NONCE, None).hex() == case["hash_no_expiry"]


@pytest.mark.parametrize("network,name", CASES)
def test_signatures_match_the_sdk(network, name):
    case, action, mainnet = V["cases"][f"{network}/{name}"], V["actions"][name], network == "mainnet"
    assert signing.sign_l1(KEYS["agent"], action, NONCE, EXPIRES, mainnet) == case["plain"]
    env = signing.envelope(ADDR["account"], ADDR["agent"], action)
    for who in ("agent", "guard"):
        assert signing.sign_l1(KEYS[who], env, NONCE, EXPIRES, mainnet) == case["cosigned"][who]
    multi = signing.multi_sig_action(ADDR["account"], ADDR["agent"], action,
                                     [case["cosigned"]["agent"], case["cosigned"]["guard"]])
    assert multi == case["multi_sig_action"]
    assert signing.sign_multi_sig(KEYS["agent"], multi, NONCE, EXPIRES, mainnet) == case["outer"]


@pytest.mark.parametrize("network,name", CASES)
def test_recover_names_the_signer(network, name):
    case, action, mainnet = V["cases"][f"{network}/{name}"], V["actions"][name], network == "mainnet"
    env = signing.envelope(ADDR["account"], ADDR["agent"], action)
    assert signing.recover_l1(env, NONCE, EXPIRES, mainnet, case["cosigned"]["guard"]) == ADDR["guard"]
    # the same signature over anything else names someone else
    assert signing.recover_l1(env, NONCE + 1, EXPIRES, mainnet, case["cosigned"]["guard"]) != ADDR["guard"]
    assert signing.recover_l1(env, NONCE, EXPIRES, not mainnet, case["cosigned"]["guard"]) != ADDR["guard"]


@pytest.mark.parametrize("network", ["mainnet", "testnet"])
def test_convert_to_multi_sig(network):
    case = V["cases"][f"{network}/convert"]
    action = {k: case["action"][k] for k in ("type", "signers", "nonce")}
    signature = signing.sign_convert_to_multi_sig(KEYS["account"], action, network == "mainnet")
    assert signature == case["signature"]
    assert action == case["action"]                                    # with the chain fields, as posted


def test_key_order_is_part_of_what_is_signed():
    action = V["actions"]["order"]
    reordered = {"grouping": action["grouping"], "orders": copy.deepcopy(action["orders"]), "type": action["type"]}
    assert signing.action_hash(reordered, NONCE, EXPIRES) != signing.action_hash(action, NONCE, EXPIRES)


@pytest.mark.parametrize("network", ["mainnet", "testnet"])
@pytest.mark.parametrize("name", ["withdraw", "to_normal"])
def test_user_signed_actions_on_a_multi_sig_account(network, name):
    case, mainnet = V["cases"][f"{network}/{name}"], network == "mainnet"
    for who in ("owner", "guard"):
        signature = signing.sign_multi_sig_user_signed(KEYS[who], case["action"], ADDR["account"], ADDR["owner"], mainnet)
        assert signature == case["signatures"][who]
        assert signing.recover_multi_sig_user_signed(case["action"], ADDR["account"], ADDR["owner"], mainnet, signature) == ADDR[who]
