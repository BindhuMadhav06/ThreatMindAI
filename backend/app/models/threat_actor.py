from typing import Optional, List
from pydantic import BaseModel, Field

class ThreatActorModel(BaseModel):
    id: str = Field(..., description="Unique ThreatActor ID, e.g., actor_apt29")
    name: str = Field(..., description="Canonical threat actor name, e.g., APT29")
    aliases: List[str] = Field(default_factory=list, description="Known aliases, e.g., ['Cozy Bear', 'The Dukes']")
    description: Optional[str] = Field(None, description="Detailed profile description")
    country: Optional[str] = Field(None, description="Attributed state origin")
