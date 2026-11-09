from taintzero.dynamic import DynamicEvent, create_canary, detect_canary


def test_canaries_are_unique_and_non_exploitable() -> None:
    first = create_canary("http.query.command")
    second = create_canary("http.query.command")

    assert first.id != second.id
    assert first.marker != second.marker
    assert first.marker.isascii()
    assert all(character.isalnum() or character == "_" for character in first.marker)


def test_detects_raw_and_encoded_canary_variants() -> None:
    canary = create_canary("http.query.url")

    assert detect_canary(f"prefix:{canary.marker}:suffix", canary) == ("raw", "url", "json")
    assert detect_canary(canary.variants["base64"].encode(), canary) == ("base64",)


def test_dynamic_event_is_machine_readable() -> None:
    canary = create_canary("cli.argument.0")
    event = DynamicEvent(
        event="sink_observed",
        canary_id=canary.id,
        input_id=canary.input_id,
        symbol="os.system",
        path="service.py",
        line=12,
        variants=("raw",),
    )

    assert event.to_dict() == {
        "event": "sink_observed",
        "canary_id": canary.id,
        "input_id": "cli.argument.0",
        "symbol": "os.system",
        "path": "service.py",
        "line": 12,
        "variants": ("raw",),
            "blocked": False,
            "schema_version": "1",
    }
