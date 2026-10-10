"""
The TypeScript client (guard/client-ts) is tested against vectors made by the
Python client. This checks the committed vectors are still what Python
produces: change an encoding here and this fails until the vectors, and so
the TypeScript tests, are brought along.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

VECTORS = Path(__file__).resolve().parents[2] / "client-ts" / "test"


def test_the_committed_vectors_are_what_the_python_client_produces():
    spec = importlib.util.spec_from_file_location("make_vectors", VECTORS / "make_vectors.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    committed = json.loads((VECTORS / "vectors.json").read_text())
    assert committed == json.loads(json.dumps(module.vectors())), (
        "guard/client-ts/test/vectors.json is stale: run guard/client-ts/test/make_vectors.py")
