"""
Phase 16: TAXII 2.1 Federation & Collaborative Sharing Service.
Implements standards-based TAXII 2.1 collections, bounded object querying,
untrusted external ingestion tagging, and non-destructive retraction workflows.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from app.models.privacy import (
    CollaborationRetractionRequest,
    SharingScope,
    TAXIICollection,
    TAXIISharingRecord,
    TLPMarking,
)
from app.services.privacy.anonymization_service import AnonymizationService
from app.services.privacy.sharing_policy_service import SharingPolicyService


class TAXIIFederationService:
    """
    Manages TAXII 2.1 collections, inbound/outbound federation,
    and tombstone-based retractions.
    """

    def __init__(
        self,
        policy_service: Optional[SharingPolicyService] = None,
        anonymization_service: Optional[AnonymizationService] = None
    ):
        self.policy_service = policy_service or SharingPolicyService()
        self.anonymizer = anonymization_service or AnonymizationService()

        # Seed standard TAXII 2.1 Collections
        self._collections: Dict[str, TAXIICollection] = {
            "collection_isac_shared": TAXIICollection(
                id="collection_isac_shared",
                title="Community ISAC Threat Feed",
                description="Verified cross-organization threat intelligence sharing channel.",
                alias="isac-feed",
                can_read=True,
                can_write=True
            ),
            "collection_public_feed": TAXIICollection(
                id="collection_public_feed",
                title="Public CTI Observable Exchange",
                description="Open source indicators and community disclosures.",
                alias="public-observables",
                can_read=True,
                can_write=False
            )
        }

        self._shared_records: Dict[str, TAXIISharingRecord] = {}
        self._collection_objects: Dict[str, List[Dict[str, Any]]] = {
            "collection_isac_shared": [],
            "collection_public_feed": []
        }

    def list_collections(self) -> List[TAXIICollection]:
        return list(self._collections.values())

    def get_collection(self, collection_id: str) -> Optional[TAXIICollection]:
        return self._collections.get(collection_id)

    def publish_object_to_collection(
        self,
        collection_id: str,
        tenant_id: str,
        obj: Dict[str, Any],
        tlp_marking: TLPMarking = TLPMarking.TLP_GREEN,
        recipient_id: Optional[str] = "isac_member_verified"
    ) -> TAXIISharingRecord:
        """
        Publish intelligence object into TAXII collection with policy authorization
        and automatic anonymization of internal identifiers.
        """
        if collection_id not in self._collections:
            raise KeyError(f"TAXII collection '{collection_id}' not found.")

        collection = self._collections[collection_id]
        if not collection.can_write:
            raise PermissionError(f"Collection '{collection_id}' is read-only.")

        # Check Sharing Policy
        is_auth, reason = self.policy_service.evaluate_export_authorization(
            tenant_id=tenant_id,
            object_tlp=tlp_marking,
            requested_scope=SharingScope.COMMUNITY_ISAC,
            recipient_id=recipient_id,
            contains_internal_identifiers=True
        )
        if not is_auth:
            raise PermissionError(reason)

        # Anonymize private internal identifiers before publishing
        sanitized_obj = dict(obj)
        for k, v in list(sanitized_obj.items()):
            if isinstance(v, str):
                if self.anonymizer.is_private_ip(v):
                    anon_ip, _ = self.anonymizer.transform_internal_ip(v, tenant_id)
                    sanitized_obj[k] = anon_ip
                elif "internal" in v or "corp" in v:
                    anon_host, _ = self.anonymizer.transform_internal_hostname(v, tenant_id)
                    sanitized_obj[k] = anon_host

        record_id = f"share_{uuid.uuid4().hex[:12]}"
        record = TAXIISharingRecord(
            record_id=record_id,
            collection_id=collection_id,
            tenant_id=tenant_id,
            object_id=sanitized_obj.get("id", f"indicator--{uuid.uuid4()}"),
            object_type=sanitized_obj.get("type", "indicator"),
            tlp_marking=tlp_marking,
            sharing_scope=SharingScope.COMMUNITY_ISAC,
            status="ACTIVE"
        )
        self._shared_records[record_id] = record
        self._collection_objects[collection_id].append(sanitized_obj)
        return record

    def get_collection_objects(
        self,
        collection_id: str,
        max_limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Retrieve bounded objects from collection."""
        if collection_id not in self._collections:
            raise KeyError(f"TAXII collection '{collection_id}' not found.")
        return self._collection_objects.get(collection_id, [])[:max_limit]

    def ingest_external_taxii_object(
        self,
        collection_id: str,
        obj: Dict[str, Any],
        source_feed_name: str = "External_TAXII_Feed"
    ) -> Dict[str, Any]:
        """
        Ingest external object received via TAXII federation.
        INVARIANT: Tagged strictly as UNTRUSTED_EXTERNAL data.
        External servers CANNOT inject trusted internal assertions.
        """
        tagged_obj = dict(obj)
        tagged_obj["threatmind_provenance"] = {
            "source_type": "UNTRUSTED_EXTERNAL_TAXII",
            "source_feed": source_feed_name,
            "collection_id": collection_id,
            "ingested_at": datetime.now(timezone.utc).isoformat(),
            "validation_status": "unverified_external"
        }
        return tagged_obj

    def retract_intelligence(self, req: CollaborationRetractionRequest) -> TAXIISharingRecord:
        """
        Retract a previously shared intelligence object.
        Preserves complete historical record with tombstone status.
        """
        record = self._shared_records.get(req.record_id)
        if not record:
            raise KeyError(f"Sharing record '{req.record_id}' not found.")
        if record.tenant_id != req.tenant_id:
            raise PermissionError("Access denied: Tenant mismatch on intelligence retraction.")

        record.status = "RETRACTED"
        record.retraction_reason = req.reason
        record.retracted_at = datetime.now(timezone.utc).isoformat()
        if req.superseding_object_id:
            record.status = "SUPERSEDED"
            record.superseded_by = req.superseding_object_id

        return record
