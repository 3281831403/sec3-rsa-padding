"""Padding checks for a small RSA-style block format.

A block is laid out as:

    scheme tag (2 bytes) | message length (2 bytes, big endian) | message | padding

The padding region must be at least ``MIN_PADDING`` bytes long and every
byte in it must be non-zero.

Security model
--------------

Validation failures must never be distinguishable from one another: every
illegal block produces the same :data:`UNIFORM_ERROR` result and failure
results never carry plaintext.  Comparisons and byte checks are written
without content-dependent branches or short-circuiting so that validity
does not leak through timing either.  Batch decryption handles each item
independently and deterministically.
"""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from typing import Any, Callable

HEADER_SIZE = 4
MIN_PADDING = 8
UNIFORM_ERROR = "decryption failed"


class PaddingError(Exception):
    """Base error for an invalid padded block."""


class HeaderError(PaddingError):
    """The block header does not match the selected scheme."""


class LengthError(PaddingError):
    """The message length does not agree with the block contents."""


def _as_bytes(value: Any) -> bytes:
    """Return a byte copy of a bytes-like value."""

    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    try:
        return bytes(value)
    except (TypeError, ValueError) as exc:
        raise TypeError("block must be bytes-like") from exc


def parse_block(block: Any) -> dict[str, Any]:
    """Parse a padded block into its header, message and padding parts.

    Parsing is deliberately a slicing operation: a caller can inspect what a
    block claims before deciding whether that claim is acceptable.
    """

    data = _as_bytes(block)
    if len(data) < HEADER_SIZE:
        raise PaddingError("block is shorter than its header")

    declared_length = int.from_bytes(data[2:4], "big")
    payload = data[HEADER_SIZE : HEADER_SIZE + declared_length]
    padding = data[HEADER_SIZE + declared_length :]

    return {
        "header": data[:HEADER_SIZE],
        "tag": data[:2],
        "declared_length": declared_length,
        "length": declared_length,
        "payload": payload,
        "message": payload,
        "padding": padding,
    }


def check_header(block: Any, scheme: Any) -> bool:
    """Return whether a block carries the scheme tag named by ``scheme``.

    The tag is compared in constant time.  Any malformed input simply
    reports ``False`` instead of raising.
    """

    try:
        parsed = parse_block(block)
    except Exception:
        return False

    if not isinstance(scheme, Mapping):
        return False
    try:
        expected_tag = _as_bytes(scheme.get("tag"))
    except Exception:
        return False
    if len(expected_tag) != 2:
        return False

    return constant_time_equal(parsed["tag"], expected_tag)


def check_length(block: Any, expected: int) -> bool:
    """Return whether the block declares and contains ``expected`` bytes.

    The length field in the header must equal ``expected`` and the block
    must actually contain that many message bytes after the header.
    """

    if not isinstance(expected, int) or isinstance(expected, bool) or expected < 0:
        return False
    try:
        parsed = parse_block(block)
        data_length = len(_as_bytes(block))
    except Exception:
        return False

    if parsed["declared_length"] != expected:
        return False
    if len(parsed["payload"]) != expected:
        return False
    if data_length < HEADER_SIZE + expected:
        return False
    return True


def check_padding_bytes(block: Any) -> bool:
    """Return whether the padding area is well formed.

    The padding area must contain at least :data:`MIN_PADDING` bytes and
    every one of them must be non-zero.  The zero scan accumulates into an
    integer instead of short-circuiting, so the position of a bad byte is
    not revealed by an early exit.
    """

    try:
        parsed = parse_block(block)
    except Exception:
        return False

    padding = parsed["padding"]
    if len(padding) < MIN_PADDING:
        return False

    zero_found = 0
    for value in padding:
        zero_found |= int(value == 0)
    return zero_found == 0


def uniform_error(fn: Callable[[], Any]) -> dict[str, Any]:
    """Run a zero-argument operation and describe success or failure.

    Every failure, regardless of its underlying reason, yields the same
    mapping so callers cannot distinguish padding, header or length
    failures from one another.
    """

    try:
        value = fn()
    except Exception:
        return {"ok": False, "error": UNIFORM_ERROR}
    return {"ok": True, "value": value}


def constant_time_equal(a: Any, b: Any) -> bool:
    """Compare two byte-like values without variable-time equality.

    Inputs are normalized to plain bytes first, so custom ``__eq__``
    implementations are never invoked, then compared with the standard
    library's constant-time digest comparison.
    """

    try:
        left = _as_bytes(a)
        right = _as_bytes(b)
    except Exception:
        return False
    try:
        return hmac.compare_digest(left, right)
    except Exception:
        return False


def validate_scheme(scheme: Any) -> list[str]:
    """Return the problems found in a padding scheme description."""

    if not isinstance(scheme, Mapping):
        return ["scheme must be a mapping"]

    issues: list[str] = []

    tag = scheme.get("tag")
    if not isinstance(tag, (bytes, bytearray, memoryview)) or len(tag) != 2:
        issues.append("tag must be exactly two bytes")

    minimum = scheme.get("min_padding")
    if (
        not isinstance(minimum, int)
        or isinstance(minimum, bool)
        or minimum < MIN_PADDING
    ):
        issues.append("min_padding must be at least eight")

    if scheme.get("uniform_errors") is not True:
        issues.append("uniform_errors must be true")

    order = scheme.get("check_order")
    if not isinstance(order, (list, tuple)):
        issues.append("check_order must list padding and length")
    elif "padding" not in order or "length" not in order:
        issues.append("check_order must list padding and length")
    elif order.index("padding") > order.index("length"):
        issues.append("padding must be checked before length")

    return issues


def _item_parts(item: Any) -> tuple[Any, int | None]:
    """Extract the block and optional expected length from a batch item."""

    if isinstance(item, Mapping):
        if "ciphertext" not in item:
            raise PaddingError("batch item has no ciphertext")
        return item["ciphertext"], item.get("expected_length")
    return item, None


def _uniform_failure() -> dict[str, Any]:
    """The single failure shape shared by every validation rejection."""

    return {"ok": False, "error": UNIFORM_ERROR}


def _decrypt_one(item: Any, scheme: Any) -> dict[str, Any]:
    """Validate one block and return its message bytes.

    All checks are evaluated unconditionally and their outcomes are only
    combined afterwards, following the scheme's declared check order.  Any
    failure produces the identical uniform result and never includes
    plaintext, so an attacker cannot tell which check rejected a block.
    """

    try:
        block, expected = _item_parts(item)
        data = _as_bytes(block)
        parsed = parse_block(data)
    except Exception:
        return _uniform_failure()

    try:
        header_ok = check_header(data, scheme)

        if expected is None:
            expected = parsed["declared_length"]
        length_ok = check_length(data, expected)
        padding_ok = check_padding_bytes(data)

        check_results = {
            "header": header_ok,
            "length": length_ok,
            "padding": padding_ok,
        }

        # Combine in the scheme's declared order (padding before length).
        # No check short-circuits the evaluation above, so every block does
        # the same amount of validation work.
        order = scheme.get("check_order", ("padding", "length"))
        valid = header_ok
        for name in order:
            valid = valid and check_results.get(name, True)
    except Exception:
        return _uniform_failure()

    if not valid:
        return _uniform_failure()

    return {"ok": True, "plaintext": parsed["payload"]}


def decrypt_batch(items: Any, scheme: Any) -> dict[str, Any]:
    """Decrypt a batch of independently padded blocks.

    Each item is validated on its own: one item's failure never aborts or
    alters the handling of another, failure entries carry no plaintext,
    and processing is deterministic so the same ciphertext always yields
    the same result.
    """

    issues = validate_scheme(scheme)
    if issues:
        return {"ok": False, "error": "invalid scheme", "results": []}

    try:
        iterator = iter(items)
    except TypeError:
        return {"ok": False, "error": UNIFORM_ERROR, "results": []}

    results: list[dict[str, Any]] = []
    for item in iterator:
        try:
            results.append(_decrypt_one(item, scheme))
        except Exception:
            results.append(_uniform_failure())

    return {
        "ok": all(result.get("ok") is True for result in results),
        "results": results,
    }
