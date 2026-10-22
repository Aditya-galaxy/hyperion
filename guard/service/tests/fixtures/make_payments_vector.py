"""Write tests/fixtures/payments_vector.json: a request and the approval for it,
from fixed keys. Payers in other languages check their own encoding against it
(MerlinClips: src/campaign/hyperion.test.ts), and test_payments_vector.py checks
it is still what this Guard produces."""

import json
from pathlib import Path

from eth_account import Account

from hyperion_guard.payments import control

GUARD, AGENT = Account.from_key("0x" + "31" * 32), Account.from_key("0x" + "32" * 32)
REQUEST = dict(agent=AGENT.address, payer="0x0003a59858f44451be2a5b486ee612b4139700f0",
               recipient="0x" + "a1" * 20, token="0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", chain="base",
               amount="12.5", intent_id="pay-sub_42-15000", expires_at=1_760_000_120, simulate=False)


def vector() -> dict:
    message = control.request_message(**REQUEST)
    typed = control.approval_typed_data(agent=REQUEST["agent"], payer=REQUEST["payer"], recipient=REQUEST["recipient"],
                                        token=REQUEST["token"], chain=REQUEST["chain"], amount_units=12_500_000,
                                        intent_id=REQUEST["intent_id"], policy_version=3, expires_at=REQUEST["expires_at"])
    return {"keys": {"guard": GUARD.key.hex(), "agent": AGENT.key.hex()},
            "addresses": {"guard": GUARD.address, "agent": AGENT.address},
            "request": REQUEST, "request_message": message,
            "request_signature": control.sign_message(AGENT.key, message),
            "approval": typed, "approval_signature": control.sign_approval(GUARD.key, typed)}


if __name__ == "__main__":
    Path(__file__).with_name("payments_vector.json").write_text(json.dumps(vector(), indent=1) + "\n")
    print("wrote payments_vector.json")
