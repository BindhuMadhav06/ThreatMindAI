import pytest
import sys
import os
from typing import Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.services.ingestion.models import TextChunk
from app.services.extraction.entity_extractor import EntityExtractor
from app.services.extraction.relation_extractor import RelationExtractor
from app.services.llm.base_provider import BaseLLMProvider

class MockLLMProvider(BaseLLMProvider):
    def get_provider_name(self) -> str:
        return "mock_test_llm"

    def is_available(self) -> bool:
        return True

    def generate_response(self, prompt: str, system_instruction=None, temperature=0.2) -> str:
        return "Mock response"

    def generate_structured_output(self, prompt: str, schema: Any, system_instruction=None) -> dict:
        if isinstance(schema, dict) and "entities" in schema.get("properties", {}):
            return {
                "entities": [
                    {"label": "ThreatActor", "name": "APT29", "aliases": ["Cozy Bear"], "description": "Threat Actor"},
                    {"label": "Malware", "name": "Cobalt Strike", "aliases": ["Beacon"], "description": "C2 Malware"}
                ]
            }
        else:
            return {
                "relationships": [
                    {
                        "source_name": "APT29",
                        "source_label": "ThreatActor",
                        "rel_type": "USES",
                        "target_name": "Cobalt Strike",
                        "target_label": "Malware",
                        "evidence_text": "APT29 deployed Cobalt Strike Beacon payloads during targeted cyber operations.",
                        "confidence": None
                    }
                ]
            }

def test_mocked_entity_extraction():
    mock_llm = MockLLMProvider()
    extractor = EntityExtractor(llm_provider=mock_llm)
    
    chunk = TextChunk(
        chunk_id="chk_001",
        source_id="src_001",
        chunk_index=0,
        text="APT29 deployed Cobalt Strike Beacon payloads during targeted cyber operations.",
        word_count=9
    )
    
    entities = extractor.extract_entities_from_chunk(chunk)
    assert len(entities) == 2
    assert entities[0].name == "APT29"
    assert entities[0].label == "ThreatActor"
    assert entities[1].name == "Cobalt Strike"
    assert entities[1].label == "Malware"

def test_mocked_relation_extraction():
    mock_llm = MockLLMProvider()
    extractor = RelationExtractor(llm_provider=mock_llm)
    
    chunk = TextChunk(
        chunk_id="chk_001",
        source_id="src_001",
        chunk_index=0,
        text="APT29 deployed Cobalt Strike Beacon payloads during targeted cyber operations.",
        word_count=9
    )
    
    rels = extractor.extract_relationships_from_chunk(chunk)
    assert len(rels) == 1
    assert rels[0].source_name == "APT29"
    assert rels[0].rel_type == "USES"
    assert rels[0].target_name == "Cobalt Strike"
    assert "Cobalt Strike Beacon" in rels[0].evidence_text
