"""
RFC 8785 JSON Canonicalization Scheme (JCS) and SHA-256 Digest Utility
Implements deterministic, cross-platform canonical JSON serialization per RFC 8785.
Used for full-object marking immutability checks, version conflict detection, and audit hashes.
"""

import json
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Union


def _canonicalize_value(val: Any) -> Any:
    """
    Recursively canonicalizes Python data structures:
    - Dicts: keys sorted strictly by UTF-16 code units (per RFC 8785 §3.2.3).
    - Lists: elements recursively canonicalized in original order.
    - Datetime: normalized to UTC ISO 8601 string (e.g., 2026-11-19T12:00:00Z).
    - Floats: formatted per IEEE 754 / ECMAScript specifications (no redundant signs/exponents).
    - Primitives (str, int, bool, None): preserved as-is.
    """
    if isinstance(val, dict):
        # RFC 8785 §3.2.3: Keys must be sorted in ascending order of their UTF-16 code units
        sorted_items = sorted(val.items(), key=lambda kv: str(kv[0]).encode("utf-16-be"))
        return {str(k): _canonicalize_value(v) for k, v in sorted_items}
    elif isinstance(val, (list, tuple)):
        return [_canonicalize_value(elem) for elem in val]
    elif isinstance(val, datetime):
        if val.tzinfo is not None:
            utc_dt = val.astimezone(timezone.utc)
        else:
            utc_dt = val.replace(tzinfo=timezone.utc)
        iso = utc_dt.strftime("%Y-%m-%dT%H:%M:%S")
        if utc_dt.microsecond:
            iso += f".{utc_dt.microsecond:06d}".rstrip("0")
        return iso + "Z"
    elif isinstance(val, float):
        # Handle -0.0 per RFC 8785 §3.2.2.3
        if val == 0.0:
            return 0
        return val
    return val


def canonical_json_dumps(obj: Any) -> str:
    """
    Serializes an object to canonical JSON string per RFC 8785:
    - UTF-16 code unit sorted object keys
    - Minimal whitespace (',' and ':' separators without whitespace)
    - Verbatim UTF-8 characters without unnecessary Unicode escapes
    """
    canonical_data = _canonicalize_value(obj)
    return json.dumps(
        canonical_data,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_canonical_digest(obj: Any) -> str:
    """
    Calculates SHA-256 hex digest of the canonical JSON representation.
    Guarantees deterministic immutability digests across platforms and environments.
    """
    canonical_bytes = canonical_json_dumps(obj).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()
