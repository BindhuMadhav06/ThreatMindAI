from typing import Optional
from pydantic import BaseModel, Field

class TechniqueModel(BaseModel):
    id: str = Field(..., description="Unique Technique ID, e.g., tech_t1059_001")
    name: str = Field(..., description="Technique name, e.g., PowerShell")
    external_id: str = Field(..., description="MITRE ATT&CK technique ID, e.g., T1059.001")
    description: Optional[str] = Field(None, description="Technique execution description")
