"""The payments vector other payers test against is still what this Guard signs."""

import json
from pathlib import Path

from fixtures.make_payments_vector import vector


def test_the_vector_is_current():
    saved = json.loads((Path(__file__).parent / "fixtures" / "payments_vector.json").read_text())
    assert saved == json.loads(json.dumps(vector()))
