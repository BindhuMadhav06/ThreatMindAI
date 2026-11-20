"""
Phase 16: Cryptographic Privacy & Anonymization Engine.

Implements persistent tenant-isolated salted HMAC transformations, PII/credential redaction,
and RFC 1918 / RFC 4193 / CGNAT / Link-Local / Documentation / Multicast address pseudonymization.
Guarantees stable pseudonymization across server restarts via persistent salt storage.
Enforces at least 128 bits of output entropy (32 hex characters) using a versioned scheme,
and strictly rejects unsalted hashing to protect against dictionary enumeration attacks.
"""

import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
from typing import Any, Dict, List, Optional, Tuple

from app.models.privacy import AnonymizationMethod, AnonymizationRecord
from app.core.logging import logger


class AnonymizationService:
    """
    Cryptographic privacy engine enforcing tenant-isolated pseudonymization
    and preventing re-identification via low-entropy brute-force attacks.
    Salts are securely persisted per tenant so pseudonyms remain stable across restarts.
    """

    def __init__(self, storage_dir: Optional[Path] = None):
        self._storage_dir = storage_dir or (Path(__file__).resolve().parents[4] / "data" / "federation")
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._salts_file = self._storage_dir / "tenant_salts.json"
        self._tenant_salts: Dict[str, bytes] = {}
        self._load_persisted_salts()

    def _load_persisted_salts(self):
        """Loads hex-encoded salts from persistent storage."""
        if self._salts_file.exists():
            try:
                with open(self._salts_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for t_id, hex_salt in data.items():
                        self._tenant_salts[t_id] = bytes.fromhex(hex_salt)
            except Exception as e:
                logger.warning(f"Could not load persisted tenant salts: {e}")

    def _save_persisted_salts(self):
        """Atomically saves tenant salts to disk."""
        try:
            data = {t_id: salt.hex() for t_id, salt in self._tenant_salts.items()}
            temp_file = self._salts_file.with_suffix(".tmp")
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            temp_file.replace(self._salts_file)
        except Exception as e:
            logger.warning(f"Could not persist tenant salts: {e}")

    def get_or_create_tenant_salt(self, tenant_id: str) -> bytes:
        """
        Retrieve or initialize a cryptographically secure 256-bit salt for tenant.
        Persists newly generated salts so pseudonyms remain stable across restarts.
        """
        clean_tenant = tenant_id.strip() or "tenant_default"
        if clean_tenant not in self._tenant_salts:
            self._tenant_salts[clean_tenant] = secrets.token_bytes(32)
            self._save_persisted_salts()
        return self._tenant_salts[clean_tenant]

    def _compute_hmac(self, value: str, tenant_id: str, version: str = "v2") -> str:
        """
        Computes keyed HMAC digest.
        Version 'v2' produces 32-hex character (128-bit) digest.
        Version 'v1' (legacy) produces 16-hex character (64-bit) digest.
        """
        salt = self.get_or_create_tenant_salt(tenant_id)
        digest = hmac.new(salt, value.encode("utf-8"), hashlib.sha256).hexdigest()
        if version == "v1":
            return digest[:16]
        return digest[:32]

    @classmethod
    def should_mask_ip(cls, ip_str: str) -> bool:
        """
        Determines whether an IP address must be masked/pseudonymized.
        Returns True for:
        - RFC 1918 Private IPv4 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
        - RFC 4193 Unique Local IPv6 (fc00::/7)
        - Loopback (127.0.0.0/8, ::1)
        - Link-Local (169.254.0.0/16, fe80::/10)
        - Carrier-Grade NAT / RFC 6598 (100.64.0.0/10)
        - Documentation TEST-NETs (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32)
        - Multicast (224.0.0.0/4, ff00::/8)
        - Reserved / Broadcast (240.0.0.0/4, 255.255.255.255)
        
        Returns False for routable public internet addresses (e.g., 8.8.8.8, 1.1.1.1, 2606:4700:4700::1111)
        which represent legitimate external C2 indicators.
        """
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            cgnat = ipaddress.ip_network("100.64.0.0/10")
            if ip_obj.version == 4 and ip_obj in cgnat:
                return True
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
                or not ip_obj.is_global
            ):
                return True
            return False
        except ValueError:
            return False

    @classmethod
    def is_private_ip(cls, ip_str: str) -> bool:
        """Backward-compatible alias for should_mask_ip."""
        return cls.should_mask_ip(ip_str)

    def transform_internal_ip(
        self, ip_str: str, tenant_id: str, version: str = "v2"
    ) -> Tuple[str, Optional[AnonymizationRecord]]:
        """
        Transforms private internal IP into a salted HMAC pseudonym with >= 128-bit output.
        Preserves external public threat indicators without modification.
        """
        clean_ip = ip_str.strip()
        if not self.should_mask_ip(clean_ip):
            # Public IP (external C2 indicator): preserved for threat correlation
            return clean_ip, None

        raw_hmac = self._compute_hmac(clean_ip, tenant_id, version=version)
        pseudonym = f"pseudonym-ip-{raw_hmac}"
        record = AnonymizationRecord(
            original_type="INTERNAL_IP",
            transformed_value=pseudonym,
            method=AnonymizationMethod.HMAC_SHA256_SALTED,
            salt_hash_ref=hashlib.sha256(self.get_or_create_tenant_salt(tenant_id)).hexdigest()[:8],
            entropy_warning=f"Non-public IP transformed via keyed HMAC ({len(raw_hmac)*4}-bit entropy) to prevent enumeration."
        )
        return pseudonym, record

    def transform_internal_hostname(
        self, hostname: str, tenant_id: str, version: str = "v2"
    ) -> Tuple[str, AnonymizationRecord]:
        """Transforms internal server FQDNs into salted HMAC pseudonyms with >= 128-bit output."""
        clean_host = hostname.strip().lower()
        raw_hmac = self._compute_hmac(clean_host, tenant_id, version=version)
        pseudonym = f"pseudonym-host-{raw_hmac}.internal"
        record = AnonymizationRecord(
            original_type="INTERNAL_HOSTNAME",
            transformed_value=pseudonym,
            method=AnonymizationMethod.HMAC_SHA256_SALTED,
            salt_hash_ref=hashlib.sha256(self.get_or_create_tenant_salt(tenant_id)).hexdigest()[:8]
        )
        return pseudonym, record

    @staticmethod
    def redact_pii_and_credentials(text: str) -> str:
        """Redacts credentials, API keys, authorization bearer tokens, and email addresses."""
        sanitized = re.sub(
            r"(?i)(bearer\s+[a-zA-Z0-9_\-\.]{15,}|password\s*[:=]\s*\S+|api[_\-]?key\s*[:=]\s*\S+)",
            "[REDACTED_CREDENTIAL]",
            text
        )
        sanitized = re.sub(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "[REDACTED_EMAIL]",
            sanitized
        )
        return sanitized

    def sanitize_recursive(self, data: Any, tenant_id: str) -> Any:
        """
        Recursively sanitizes nested dictionaries, lists, and strings:
        - Redacts PII and credentials
        - Pseudonymizes internal/non-public IPv4 and IPv6 addresses
        - Pseudonymizes internal hostnames (.internal, .corp, .local)
        - Preserves public routable C2 IPs and public external domain names
        """
        if isinstance(data, dict):
            return {k: self.sanitize_recursive(v, tenant_id) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.sanitize_recursive(item, tenant_id) for item in data]
        elif isinstance(data, str):
            text = self.redact_pii_and_credentials(data)

            # If the entire string is just a single IP address
            clean_str = text.strip()
            if self.should_mask_ip(clean_str):
                anon_ip, _ = self.transform_internal_ip(clean_str, tenant_id)
                return anon_ip

            # If the entire string is just a single internal hostname
            if any(clean_str.lower().endswith(suffix) for suffix in (".internal", ".corp", ".local")) and " " not in clean_str:
                anon_host, _ = self.transform_internal_hostname(clean_str, tenant_id)
                return anon_host

            # In free-text sentences, replace internal hostnames via regex
            text = re.sub(
                r'\b[a-zA-Z0-9_\-\.]+\.(?:corp|internal|local)\b',
                lambda m: self.transform_internal_hostname(m.group(0), tenant_id)[0],
                text
            )

            # In free-text sentences, replace standalone non-public IPv4 addresses
            def _replace_ip(m):
                cand_ip = m.group(0)
                if self.should_mask_ip(cand_ip):
                    return self.transform_internal_ip(cand_ip, tenant_id)[0]
                return cand_ip

            text = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', _replace_ip, text)
            return text
        else:
            return data
