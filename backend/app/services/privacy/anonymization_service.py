"""
Phase 16: Cryptographic Privacy & Anonymization Engine.
Implements tenant-isolated salted HMAC transformations, PII/credential redaction,
and RFC 1918 private address pseudonymization.
Strictly rejects unsalted hashing to protect against dictionary enumeration attacks.
"""

import hashlib
import hmac
import ipaddress
import re
import secrets
from typing import Dict, List, Optional, Tuple

from app.models.privacy import AnonymizationMethod, AnonymizationRecord


class AnonymizationService:
    """
    Cryptographic privacy engine enforcing tenant-isolated pseudonymization
    and preventing re-identification via low-entropy brute-force attacks.
    """

    def __init__(self):
        # Per-tenant isolated cryptographic salts (never shared across tenants)
        self._tenant_salts: Dict[str, bytes] = {}

    def get_or_create_tenant_salt(self, tenant_id: str) -> bytes:
        """Retrieve or initialize a cryptographically secure 256-bit salt for tenant."""
        if tenant_id not in self._tenant_salts:
            self._tenant_salts[tenant_id] = secrets.token_bytes(32)
        return self._tenant_salts[tenant_id]

    def _compute_hmac(self, value: str, tenant_id: str) -> str:
        salt = self.get_or_create_tenant_salt(tenant_id)
        digest = hmac.new(salt, value.encode("utf-8"), hashlib.sha256).hexdigest()
        return digest[:12]

    PRIVATE_NETWORKS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("fc00::/7"),
        ipaddress.ip_network("::1/128"),
    ]

    @classmethod
    def is_private_ip(cls, ip_str: str) -> bool:
        """Check if an IPv4 or IPv6 address belongs strictly to private/internal ranges (RFC 1918/4193)."""
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            return any(ip_obj in net for net in cls.PRIVATE_NETWORKS)
        except ValueError:
            return False

    def transform_internal_ip(self, ip_str: str, tenant_id: str) -> Tuple[str, Optional[AnonymizationRecord]]:
        """
        Transforms private internal IP into a salted HMAC pseudonym.
        Preserves external public threat indicators without modification.
        """
        clean_ip = ip_str.strip()
        if not self.is_private_ip(clean_ip):
            # Public IP (external C2 indicator): preserved for threat correlation
            return clean_ip, None

        pseudonym = f"pseudonym-ip-{self._compute_hmac(clean_ip, tenant_id)}"
        record = AnonymizationRecord(
            original_type="INTERNAL_IP",
            transformed_value=pseudonym,
            method=AnonymizationMethod.HMAC_SHA256_SALTED,
            salt_hash_ref=hashlib.sha256(self.get_or_create_tenant_salt(tenant_id)).hexdigest()[:8],
            entropy_warning="Private RFC1918 IP transformed via keyed HMAC to prevent rainbow enumeration."
        )
        return pseudonym, record

    def transform_internal_hostname(self, hostname: str, tenant_id: str) -> Tuple[str, AnonymizationRecord]:
        """
        Transforms internal server FQDNs into salted HMAC pseudonyms.
        """
        clean_host = hostname.strip().lower()
        pseudonym = f"pseudonym-host-{self._compute_hmac(clean_host, tenant_id)}.internal"
        record = AnonymizationRecord(
            original_type="INTERNAL_HOSTNAME",
            transformed_value=pseudonym,
            method=AnonymizationMethod.HMAC_SHA256_SALTED,
            salt_hash_ref=hashlib.sha256(self.get_or_create_tenant_salt(tenant_id)).hexdigest()[:8]
        )
        return pseudonym, record

    @staticmethod
    def redact_pii_and_credentials(text: str) -> str:
        """
        Redacts credentials, API keys, authorization bearer tokens, and email addresses.
        """
        # Redact Bearer / API keys
        sanitized = re.sub(
            r"(?i)(bearer\s+[a-zA-Z0-9_\-\.]{15,}|password\s*[:=]\s*\S+|api[_\-]?key\s*[:=]\s*\S+)",
            "[REDACTED_CREDENTIAL]",
            text
        )
        # Redact email addresses
        sanitized = re.sub(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "[REDACTED_EMAIL]",
            sanitized
        )
        return sanitized

    @staticmethod
    def generalize_subnet(ip_str: str) -> str:
        """Generalize private IPv4 address to /24 subnet boundary for aggregation."""
        try:
            ip_obj = ipaddress.ip_interface(f"{ip_str.strip()}/24")
            return str(ip_obj.network)
        except ValueError:
            return ip_str
