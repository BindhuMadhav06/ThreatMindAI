"""
Phase 16: Sharing Policy Engine.
Evaluates TLP markings, recipient identity authorization, data classification,
and privacy guardrails before permitting threat intelligence export or federation.
"""

from typing import Dict, List, Optional, Tuple
from app.models.privacy import SharingPolicy, SharingScope, TLPMarking


class SharingPolicyService:
    """
    Enforces multi-tenant data boundaries, TLP markings, and sharing governance.
    Fails closed on any ambiguous, unauthenticated, or unmapped sharing request.
    """

    def __init__(self):
        self._policies_by_tenant: Dict[str, SharingPolicy] = {}

    def get_or_create_policy(self, tenant_id: str) -> SharingPolicy:
        """Retrieve or create default private sharing policy for tenant."""
        if tenant_id not in self._policies_by_tenant:
            self._policies_by_tenant[tenant_id] = SharingPolicy(
                policy_id=f"policy_{tenant_id}",
                tenant_id=tenant_id,
                default_scope=SharingScope.PRIVATE_TENANT,
                allowed_scopes=[SharingScope.PRIVATE_TENANT, SharingScope.COMMUNITY_ISAC],
                require_hmac_anonymization=True,
                max_tlp_export=TLPMarking.TLP_AMBER,
                allowed_recipients=["isac_member_verified", "cert_us_cisa"],
                allowed_taxii_collections=["collection_isac_shared"]
            )
        return self._policies_by_tenant[tenant_id]

    def update_policy(self, policy: SharingPolicy) -> SharingPolicy:
        self._policies_by_tenant[policy.tenant_id] = policy
        return policy

    def evaluate_export_authorization(
        self,
        tenant_id: str,
        object_tlp: TLPMarking,
        requested_scope: SharingScope,
        recipient_id: Optional[str] = None,
        contains_internal_identifiers: bool = False
    ) -> Tuple[bool, str]:
        """
        Evaluate if an intelligence claim or bundle is authorized for external sharing.
        Returns (is_authorized, rationale).
        """
        # Rule 1: TLP:RED Suppression (Strict absolute invariant)
        if object_tlp == TLPMarking.TLP_RED:
            if requested_scope != SharingScope.PRIVATE_TENANT:
                return False, "Export Denied: TLP:RED intelligence strictly restricted to internal private tenant scope."

        policy = self.get_or_create_policy(tenant_id)

        # Rule 2: Allowed Scopes check
        if requested_scope not in policy.allowed_scopes:
            return False, f"Export Denied: Scope '{requested_scope.value}' is not permitted by tenant sharing policy."

        # Rule 3: Recipient Authorization check for AMBER / ISAC sharing
        if object_tlp in (TLPMarking.TLP_AMBER, TLPMarking.TLP_AMBER_STRICT) or requested_scope == SharingScope.COMMUNITY_ISAC:
            if not recipient_id or recipient_id not in policy.allowed_recipients:
                return False, f"Export Denied: Recipient '{recipient_id}' is not authorized for AMBER/ISAC intelligence sharing."

        # Rule 4: Internal Identifiers Check
        if contains_internal_identifiers:
            if policy.require_hmac_anonymization:
                return True, "Export Approved: Internal identifiers must undergo salted HMAC anonymization prior to transmission."
            else:
                return False, "Export Denied: Raw internal identifiers detected and anonymization is disabled."

        return True, "Export Approved: Sharing request satisfies tenant policy and TLP markings."
