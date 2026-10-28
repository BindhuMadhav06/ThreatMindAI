from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class ParsedDocument(BaseModel):
    source_id: str = Field(..., description="Unique Source ID")
    title: str = Field(..., description="Document or advisory title")
    url: Optional[str] = Field(None, description="Source URL if available")
    publisher: Optional[str] = Field(None, description="Publisher organization")
    published_date: Optional[str] = Field(None, description="Publication date (YYYY-MM-DD)")
    source_type: str = Field("cti_report", description="Format/type: pdf, html, json, txt")
    raw_text: str = Field(..., description="Full extracted text content")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional document metadata")
    is_synthetic: bool = Field(False, description="Marker if document is synthetic/demo")

class TextChunk(BaseModel):
    chunk_id: str = Field(..., description="Unique Chunk ID")
    source_id: str = Field(..., description="Parent Source ID")
    chunk_index: int = Field(..., description="Sequential chunk index")
    text: str = Field(..., description="Chunk text content")
    word_count: int = Field(..., description="Number of words in chunk")

class ExtractedEntity(BaseModel):
    id: str = Field(..., description="Entity unique ID, e.g. actor_apt29")
    label: str = Field(..., description="Primary node label from PRIMARY_NODE_LABELS")
    name: str = Field(..., description="Canonical entity name")
    aliases: List[str] = Field(default_factory=list, description="Known aliases")
    description: Optional[str] = Field(None, description="Entity description")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Additional properties")

class ExtractedRelationship(BaseModel):
    source_name: str = Field(..., description="Source entity name, e.g. APT29")
    source_label: str = Field(..., description="Source entity node label")
    rel_type: str = Field(..., description="Relationship type from SUPPORTED_RELATIONSHIPS")
    target_name: str = Field(..., description="Target entity name, e.g. Cobalt Strike")
    target_label: str = Field(..., description="Target entity node label")
    evidence_text: str = Field(..., description="MANDATORY exact supporting text quote from document")
    confidence: Optional[float] = Field(None, description="Confidence score if quantitatively calculated")

class ValidationResult(BaseModel):
    accepted_relationships: List[ExtractedRelationship] = Field(default_factory=list)
    rejected_relationships: List[Dict[str, Any]] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)

class IngestionResponse(BaseModel):
    source_id: str
    title: str
    chunks_count: int
    entities_extracted: int
    relationships_extracted: int
    relationships_accepted: int
    relationships_rejected: int
    warnings: List[str] = Field(default_factory=list)
    status: str = "success"
