"""
Phase 16: Privacy-Preserving Collaborative Intelligence — Data Models
Implements multi-boundary sharing policies, salted HMAC identifier transformation,
TLP recipient enforcement, and TAXII 2.1 collection federation records.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class SharingScope(str, Enum):
    PRIVATE_TENANT = "PRIVATE_TENANT"
    ORGANIZATION_APPROVED = "ORGANIZATION_APPROVED"
    COMMUNITY_ISAC = "COMMUNITY_ISAC"
    PUBLIC_COMMUNITY = "PUBLIC_COMMUNITY"


class DataClassification(str, Enum):
    INTERNAL = "INTERNAL"
    RESTRICTED = "RESTRICTED"
    CONFIDENTIAL = "CONFIDENTIAL"
    PUBLIC = "PUBLIC"


class TLPMarking(str, Enum):
    TLP_CLEAR = "TLP:CLEAR"
    TLP_GREEN = "TLP:GREEN"
    TLP_AMBER = "TLP:AMBER"
    TLP_AMBER_STRICT = "TLP:AMBER+STRICT"
    TLP_RED = "TLP:RED"


class AnonymizationMethod(str, Enum):
    HMAC_SHA256_SALTED = "HMAC_SHA256_SALTED"
    REDACTION = "REDACTION"
    TOKENIZATION = "TOKENIZATION"
    GENERALIZATION = "GENERALIZATION"


class AnonymizationRecord(BaseModel):
    """
    Record of privacy transformation applied to an internal identifier.
    Documents the cryptographic transformation while preventing brute-force enumeration.
    """
    original_type: Literal["INTERNAL_IP", "INTERNAL_HOSTNAME", "ASSET_ID", "CREDENTIAL", "USER_PII"]
    transformed_value: str
    method: AnonymizationMethod
    salt_hash_ref: str
    entropy_warning: Optional[str] = None


class SharingPolicy(BaseModel):
    """
    Policy governing whether an intelligence object or graph node can be shared,
    and what privacy transformations must be enforced before export.
    """
    policy_id: str
    tenant_id: str
    default_scope: SharingScope = SharingScope.PRIVATE_TENANT
    allowed_scopes: List[SharingScope] = Field(
        default_factory=lambda: [SharingScope.PRIVATE_TENANT]
    )
    require_hmac_anonymization: bool = True
    max_tlp_export: TLPMarking = TLPMarking.TLP_AMBER
    allowed_recipients: List[str] = Field(default_factory=list)
    allowed_taxii_collections: List[str] = Field(default_factory=list)
    expiration_days: Optional[int] = 90
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class TAXIICollection(BaseModel):
    """
    TAXII 2.1 Collection representation supporting authenticated discovery,
    content negotiation, and bounded object retrieval.
    """
    id: str
    title: str
    description: Optional[str] = None
    alias: Optional[str] = None
    can_read: bool = True
    can_write: bool = False
    media_types: List[str] = Field(
        default_factory=lambda: ["application/taxii+json;version=2.1", "application/stix+json;version=2.1"]
    )


class TAXIISharingRecord(BaseModel):
    """
    Persistent record of intelligence shared across TAXII federation collections.
    Supports tombstone retractions and superseding without erasing audit history.
    """
    record_id: str
    collection_id: str
    tenant_id: str
    object_id: str
    object_type: str
    tlp_marking: TLPMarking
    sharing_scope: SharingScope
    status: Literal["ACTIVE", "RETRACTED", "SUPERSEDED"] = "ACTIVE"
    superseded_by: Optional[str] = None
    retraction_reason: Optional[str] = None
    retracted_at: Optional[str] = None
    shared_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class CollaborationRetractionRequest(BaseModel):
    record_id: str
    tenant_id: str
    reason: str
    analyst_id: str
    superseding_object_id: Optional[str] = None
