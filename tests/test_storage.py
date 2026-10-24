from __future__ import annotations

import json

from apple_apns_courier.storage import read_secret, save_token_state


def test_token_state_round_trip(tmp_path) -> None:
    base = b"b" * 32
    scoped = b"s" * 32
    metadata = save_token_state(tmp_path, "com.example.app", base, scoped)
    assert read_secret(tmp_path / "base-token.bin") == base
    assert read_secret(tmp_path / "scoped-token.bin") == scoped
    assert metadata["topic"] == "com.example.app"
    assert json.loads((tmp_path / "metadata.json").read_text()) == metadata
