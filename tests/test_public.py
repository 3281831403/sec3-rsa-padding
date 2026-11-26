from engine.rsapad import check

SCHEME = {
    "name": "pkcs1v15",
    "tag": b"\x00\x02",
    "min_padding": 8,
    "uniform_errors": True,
    "check_order": ("padding", "length"),
}


def _block(
    payload: bytes,
    *,
    tag: bytes = b"\x00\x02",
    declared_length: int | None = None,
    padding: bytes = b"\xaa" * 8,
) -> bytes:
    if declared_length is None:
        declared_length = len(payload)
    return tag + declared_length.to_bytes(2, "big") + payload + padding


class _NoEquality:
    def __init__(self, raw: bytes) -> None:
        self._raw = raw

    def __bytes__(self) -> bytes:
        return self._raw

    def __eq__(self, other: object) -> bool:
        raise AssertionError("ordinary equality was used")


def _raiser(exc: Exception):
    def raise_it():
        raise exc

    return raise_it


def test_public_header_validation_rejects_wrong_scheme():
    wrong = _block(b"hello", tag=b"\x00\x01")

    assert check.check_header(wrong, SCHEME) is False


def test_public_length_mismatch_is_rejected_without_partial_plaintext():
    block = _block(b"hello")

    entry = check.decrypt_batch(
        [{"ciphertext": block, "expected_length": 6}], SCHEME
    )["results"][0]

    assert entry["ok"] is False
    assert "plaintext" not in entry


def test_public_constant_time_compare_does_not_use_ordinary_equality():
    assert check.constant_time_equal(_NoEquality(b"same"), _NoEquality(b"same")) is True
    assert check.constant_time_equal(_NoEquality(b"same"), _NoEquality(b"diff")) is False


def test_public_uniform_error_does_not_distinguish_reasons():
    length_failure = check.uniform_error(_raiser(check.LengthError("length")))
    padding_failure = check.uniform_error(_raiser(check.PaddingError("padding")))

    assert length_failure == padding_failure == {
        "ok": False,
        "error": "decryption failed",
    }


def test_public_batch_requests_stay_independent():
    result = check.decrypt_batch(
        [
            {"ciphertext": _block(b"alpha")},
            {"ciphertext": _block(b"bravo")},
        ],
        SCHEME,
    )

    assert [entry["plaintext"] for entry in result["results"]] == [b"alpha", b"bravo"]