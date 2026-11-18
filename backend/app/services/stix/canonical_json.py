"""
RFC 8785 JSON Canonicalization Scheme (JCS) and SHA-256 Digest Utility
Used for full-object marking immutability checks and version conflict detection.
"""

import json
import hashlib
from datetime import datetime, timezone
from typing import Any


def _canonical_default(o: Any) -> Any:
    """
    Encodes non-standard JSON types into canonical representations:
    - datetime: normalized to UTC and formatted as ISO 8601 string
    """
    if isinstance(o, datetime):
        if o.tzinfo is not None:
            utc_dt = o.astimezone(timezone.utc)
        else:
            utc_dt = o.replace(tzinfo=timezone.utc)
        iso = utc_dt.strftime("%Y-%m-%dT%H:%M:%S")
        if utc_dt.microsecond:
            iso += f".{utc_dt.microsecond:06d}".rstrip("0")
        return iso + "Z"
    raise TypeError(f"Object of type {o.__class__.__name__} is not JSON serializable")


def canonical_json_dumps(obj: Any) -> str:
    """
    Serializes a Python object to canonical JSON per RFC 8785:
    - Keys sorted lexicographically
    - Compact separators (',', ':') without whitespace
    - UTF-8 characters preserved (ensure_ascii=False)
    - Canonical UTC datetime handling
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_canonical_default,
    )


def compute_canonical_digest(obj: Any) -> str:
    """
    Calculates SHA-256 hex digest of the canonical JSON representation.
    """
    canonical_str = canonical_json_dumps(obj)
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
