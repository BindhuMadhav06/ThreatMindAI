from typing import Optional
from pydantic import BaseModel, Field

class SourceModel(BaseModel):
    id: str = Field(..., description="Unique Source identifier, e.g., source_mitre_apt29")
    title: str = Field(..., description="Document or report title")
    url: Optional[str] = Field(None, description="Public URL of the CTI advisory/report")
    publisher: Optional[str] = Field(None, description="Publisher organization, e.g., MITRE, CISA, Mandiant")
    published_date: Optional[str] = Field(None, description="Publication date string (YYYY-MM-DD)")
    source_type: str = Field("cti_report", description="Source type (e.g. cti_report, mitre_stix, demo_synthetic)")
    is_synthetic: bool = Field(False, description="Explicit marker indicating if source data is synthetic/demo")
