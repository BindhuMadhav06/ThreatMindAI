"""
Pydantic v2 STIX 2.1 Domain & Relationship Models
Implements OASIS STIX 2.1 Errata 01 Specification & FIRST TLP 2.0 Compatibility.
"""

from datetime import datetime
from typing import Annotated, Any, Dict, List, Literal, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, model_validator


class StixExternalReference(BaseModel):
    model_config = ConfigDict(extra="allow")

    source_name: str
    description: Optional[str] = None
    url: Optional[str] = None
    external_id: Optional[str] = None
    hashes: Optional[Dict[str, str]] = None


class StixGranularMarking(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lang: Optional[str] = None
    marking_ref: Optional[str] = None
    selectors: List[str] = Field(..., min_length=1)

    @model_validator(mode="after")
    def validate_exactly_one_target(self) -> "StixGranularMarking":
        has_lang = self.lang is not None
        has_ref = self.marking_ref is not None
        if has_lang == has_ref:
            raise ValueError(
                "GranularMarking must contain exactly one of 'lang' or 'marking_ref'. "
                f"Got lang={self.lang}, marking_ref={self.marking_ref}."
            )
        return self


class FirstTlpExtensionData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    extension_type: Literal["property-extension"] = "property-extension"
    first_tlp_label: Literal["CLEAR", "GREEN", "AMBER", "RED"]
    strict_restriction: bool
    sharing_scope: Literal[
        "all",
        "community",
        "organization_and_clients",
        "organization_only",
        "individual",
    ]
    source_handling_statement: Optional[str] = None

    @model_validator(mode="after")
    def validate_security_matrix(self) -> "FirstTlpExtensionData":
        label = self.first_tlp_label
        strict = self.strict_restriction
        scope = self.sharing_scope

        if label == "CLEAR":
            if strict is not False or scope != "all":
                raise ValueError("TLP:CLEAR requires strict_restriction=False and sharing_scope='all'")
        elif label == "GREEN":
            if strict is not False or scope != "community":
                raise ValueError("TLP:GREEN requires strict_restriction=False and sharing_scope='community'")
        elif label == "AMBER":
            if not strict and scope != "organization_and_clients":
                raise ValueError("Standard TLP:AMBER requires strict_restriction=False and sharing_scope='organization_and_clients'")
            elif strict and scope != "organization_only":
                raise ValueError("TLP:AMBER+STRICT requires strict_restriction=True and sharing_scope='organization_only'")
        elif label == "RED":
            if strict is not False or scope != "individual":
                raise ValueError("TLP:RED requires strict_restriction=False and sharing_scope='individual'")
        return self


class StixExtensionDefinition(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: Literal["extension-definition"] = "extension-definition"
    spec_version: Literal["2.1"] = "2.1"
    id: str = Field(..., pattern=r"^extension-definition--[0-9a-fA-F-]{36}$")
    created: datetime
    modified: datetime
    name: str
    description: Optional[str] = None
    created_by_ref: Optional[str] = None
    version: str
    extension_types: List[str]
    schema_uri: str = Field(..., alias="schema")


class StixMarkingDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["marking-definition"] = "marking-definition"
    spec_version: Literal["2.1"] = "2.1"
    id: str = Field(..., pattern=r"^marking-definition--[0-9a-fA-F-]{36}$")
    created: datetime
    name: Optional[str] = None
    created_by_ref: Optional[str] = None
    external_references: Optional[List[StixExternalReference]] = None
    object_marking_refs: Optional[List[str]] = None
    granular_marking_refs: Optional[List[str]] = None  # STIX 2.1 §7.2
    definition_type: Optional[str] = None
    definition: Optional[Dict[str, Any]] = None
    extensions: Optional[Dict[str, Any]] = None

    @model_validator(mode="after")
    def validate_definition_representation(self) -> "StixMarkingDefinition":
        has_legacy = self.definition_type is not None and self.definition is not None
        has_extension = bool(self.extensions)
        if not has_legacy and not has_extension:
            raise ValueError(
                "MarkingDefinition must contain either legacy (definition_type and definition) "
                "or a valid marking extension in 'extensions'."
            )
        return self


class StixCommonSdoMetadata(BaseModel):
    model_config = ConfigDict(extra="allow")

    spec_version: Literal["2.1"] = "2.1"
    id: str
    created: datetime
    modified: datetime
    description: Optional[str] = None
    created_by_ref: Optional[str] = None
    revoked: Optional[bool] = None
    labels: Optional[List[str]] = None
    confidence: Optional[int] = Field(None, ge=0, le=100)
    lang: Optional[str] = None
    external_references: Optional[List[StixExternalReference]] = None
    object_marking_refs: Optional[List[str]] = None
    granular_markings: Optional[List[StixGranularMarking]] = None
    extensions: Optional[Dict[str, Any]] = None

    @model_validator(mode="after")
    def forbid_sdo_defanged(self) -> "StixCommonSdoMetadata":
        if hasattr(self, "defanged") or (self.__pydantic_extra__ and "defanged" in self.__pydantic_extra__):
            raise ValueError("Property 'defanged' is exclusively valid on SCOs and is strictly forbidden on SDOs.")
        return self


class StixThreatActor(StixCommonSdoMetadata):
    type: Literal["threat-actor"] = "threat-actor"
    id: str = Field(..., pattern=r"^threat-actor--[0-9a-fA-F-]{36}$")
    name: str
    description: Optional[str] = None
    threat_actor_types: Optional[List[str]] = None
    aliases: Optional[List[str]] = None
    roles: Optional[List[str]] = None
    goals: Optional[List[str]] = None
    sophistication: Optional[str] = None
    resource_level: Optional[str] = None
    primary_motivation: Optional[str] = None
    secondary_motivations: Optional[List[str]] = None
    personal_motivations: Optional[List[str]] = None


class StixIntrusionSet(StixCommonSdoMetadata):
    type: Literal["intrusion-set"] = "intrusion-set"
    id: str = Field(..., pattern=r"^intrusion-set--[0-9a-fA-F-]{36}$")
    name: str
    description: Optional[str] = None
    aliases: Optional[List[str]] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    goals: Optional[List[str]] = None
    resource_level: Optional[str] = None
    primary_motivation: Optional[str] = None
    secondary_motivations: Optional[List[str]] = None


class StixCampaign(StixCommonSdoMetadata):
    type: Literal["campaign"] = "campaign"
    id: str = Field(..., pattern=r"^campaign--[0-9a-fA-F-]{36}$")
    name: str
    description: Optional[str] = None
    aliases: Optional[List[str]] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    objective: Optional[str] = None


class StixMalware(StixCommonSdoMetadata):
    type: Literal["malware"] = "malware"
    id: str = Field(..., pattern=r"^malware--[0-9a-fA-F-]{36}$")
    name: str
    is_family: bool
    description: Optional[str] = None
    aliases: Optional[List[str]] = None
    malware_types: Optional[List[str]] = None
    architecture_execution_envs: Optional[List[str]] = None
    implementation_languages: Optional[List[str]] = None
    capabilities: Optional[List[str]] = None


class StixTool(StixCommonSdoMetadata):
    type: Literal["tool"] = "tool"
    id: str = Field(..., pattern=r"^tool--[0-9a-fA-F-]{36}$")
    name: str
    description: Optional[str] = None
    aliases: Optional[List[str]] = None
    tool_types: Optional[List[str]] = None
    tool_version: Optional[str] = None


class StixVulnerability(StixCommonSdoMetadata):
    type: Literal["vulnerability"] = "vulnerability"
    id: str = Field(..., pattern=r"^vulnerability--[0-9a-fA-F-]{36}$")
    name: str
    description: Optional[str] = None


class StixAttackPattern(StixCommonSdoMetadata):
    type: Literal["attack-pattern"] = "attack-pattern"
    id: str = Field(..., pattern=r"^attack-pattern--[0-9a-fA-F-]{36}$")
    name: str
    description: Optional[str] = None
    aliases: Optional[List[str]] = None
    kill_chain_phases: Optional[List[Dict[str, Any]]] = None


class StixCourseOfAction(StixCommonSdoMetadata):
    type: Literal["course-of-action"] = "course-of-action"
    id: str = Field(..., pattern=r"^course-of-action--[0-9a-fA-F-]{36}$")
    name: str
    description: Optional[str] = None
    action: Optional[Dict[str, Any]] = None


class StixIdentity(StixCommonSdoMetadata):
    type: Literal["identity"] = "identity"
    id: str = Field(..., pattern=r"^identity--[0-9a-fA-F-]{36}$")
    name: str
    identity_class: Literal["individual", "organization", "group", "class", "system", "unknown"]
    description: Optional[str] = None
    sectors: Optional[List[str]] = None
    contact_information: Optional[str] = None


class StixIndicator(StixCommonSdoMetadata):
    type: Literal["indicator"] = "indicator"
    id: str = Field(..., pattern=r"^indicator--[0-9a-fA-F-]{36}$")
    name: Optional[str] = None
    description: Optional[str] = None
    pattern: str
    pattern_type: str
    valid_from: datetime
    valid_until: Optional[datetime] = None
    indicator_types: Optional[List[str]] = None


class StixInfrastructure(StixCommonSdoMetadata):
    type: Literal["infrastructure"] = "infrastructure"
    id: str = Field(..., pattern=r"^infrastructure--[0-9a-fA-F-]{36}$")
    name: str
    description: Optional[str] = None
    infrastructure_types: Optional[List[str]] = None
    aliases: Optional[List[str]] = None


class StixLocation(StixCommonSdoMetadata):
    type: Literal["location"] = "location"
    id: str = Field(..., pattern=r"^location--[0-9a-fA-F-]{36}$")
    name: Optional[str] = None
    description: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    precision: Optional[float] = None
    region: Optional[str] = None
    country: Optional[str] = None
    administrative_area: Optional[str] = None
    city: Optional[str] = None
    street_address: Optional[str] = None
    postal_code: Optional[str] = None


class StixReport(StixCommonSdoMetadata):
    type: Literal["report"] = "report"
    id: str = Field(..., pattern=r"^report--[0-9a-fA-F-]{36}$")
    name: str
    description: Optional[str] = None
    published: datetime
    object_refs: List[str] = Field(..., min_length=1)


SupportedStixSdo = Annotated[
    Union[
        StixThreatActor,
        StixIntrusionSet,
        StixCampaign,
        StixMalware,
        StixTool,
        StixVulnerability,
        StixAttackPattern,
        StixCourseOfAction,
        StixIdentity,
        StixIndicator,
        StixInfrastructure,
        StixLocation,
        StixReport,
    ],
    Field(discriminator="type"),
]


class StixRelationship(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: Literal["relationship"] = "relationship"
    spec_version: Literal["2.1"] = "2.1"
    id: str = Field(..., pattern=r"^relationship--[0-9a-fA-F-]{36}$")
    created: datetime
    modified: datetime
    relationship_type: str
    source_ref: str
    target_ref: str
    description: Optional[str] = None
    start_time: Optional[datetime] = None
    stop_time: Optional[datetime] = None
    created_by_ref: Optional[str] = None
    revoked: Optional[bool] = None
    labels: Optional[List[str]] = None
    confidence: Optional[int] = Field(None, ge=0, le=100)
    lang: Optional[str] = None
    external_references: Optional[List[StixExternalReference]] = None
    object_marking_refs: Optional[List[str]] = None
    granular_markings: Optional[List[StixGranularMarking]] = None
    extensions: Optional[Dict[str, Any]] = None

    @model_validator(mode="after")
    def forbid_sro_defanged(self) -> "StixRelationship":
        if hasattr(self, "defanged") or (self.__pydantic_extra__ and "defanged" in self.__pydantic_extra__):
            raise ValueError("Property 'defanged' is exclusively valid on SCOs and is strictly forbidden on SROs.")
        return self


class StixBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["bundle"] = "bundle"
    id: str = Field(..., pattern=r"^bundle--[0-9a-fA-F-]{36}$")
    objects: List[Dict[str, Any]] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def check_spec_version_forbidden_at_bundle_root(cls, data: Any) -> Any:
        if isinstance(data, dict) and "spec_version" in data:
            raise ValueError(
                "STIX 2.1 §2.1 Invariant Violation: 'spec_version' MUST NOT be present at bundle root."
            )
        return data
