from typing import Optional, Dict, Any
from app.services.ingestion.models import ParsedDocument, IngestionResponse
from app.services.ingestion.chunker import TextChunker
from app.services.extraction.entity_extractor import EntityExtractor
from app.services.extraction.relation_extractor import RelationExtractor
from app.services.normalization.normalizer import EntityNormalizer
from app.services.ingestion.validator import EvidenceValidator
from app.services.graph.repository import graph_repository
from app.core.logging import logger

class IngestionPipeline:
    def __init__(self, llm_provider=None, repo=graph_repository):
        self.entity_extractor = EntityExtractor(llm_provider=llm_provider)
        self.relation_extractor = RelationExtractor(llm_provider=llm_provider)
        self.validator = EvidenceValidator()
        self.repo = repo

    def process_document(self, doc: ParsedDocument) -> IngestionResponse:
        logger.info(f"Starting CTI ingestion pipeline for document '{doc.title}' (Source ID: {doc.source_id})")

        # Stage 1: Persist Source Node in Neo4j
        source_props = {
            "id": doc.source_id,
            "title": doc.title,
            "url": doc.url,
            "publisher": doc.publisher,
            "published_date": doc.published_date,
            "source_type": doc.source_type,
            "is_synthetic": doc.is_synthetic
        }
        self.repo.create_or_update_entity("Source", source_props)

        # Stage 2: Chunk Document Text
        chunks = TextChunker.chunk_document(doc)
        logger.info(f"Document split into {len(chunks)} text chunks.")

        extracted_entities_map = {}  # id -> ExtractedEntity
        raw_relationships = []

        # Stage 3: Entity & Relationship Extraction per Chunk
        for chunk in chunks:
            raw_ents = self.entity_extractor.extract_entities_from_chunk(chunk)
            for ent in raw_ents:
                norm_ent = EntityNormalizer.normalize_entity(ent)
                extracted_entities_map[norm_ent.id] = norm_ent

            known_entity_list = [{"name": e.name, "label": e.label} for e in extracted_entities_map.values()]
            raw_rels = self.relation_extractor.extract_relationships_from_chunk(chunk, known_entity_list)
            for rel in raw_rels:
                norm_rel = EntityNormalizer.normalize_relationship(rel)
                raw_relationships.append(norm_rel)

        # Stage 4: Evidence Validation Layer
        validation_result = self.validator.validate_relationships(doc, raw_relationships)

        # Stage 5: Idempotent Neo4j Persistence
        # A. Persist Normalized Entities
        for ent_id, entity in extracted_entities_map.items():
            props = {
                "id": entity.id,
                "name": entity.name,
                "aliases": entity.aliases,
                "description": entity.description,
                "is_synthetic": doc.is_synthetic
            }
            props.update(entity.properties)
            self.repo.create_or_update_entity(entity.label, props)

        # B. Persist Validated Relationships with Provenance
        for rel in validation_result.accepted_relationships:
            # Resolve source and target IDs via entity normalizer
            src_entity = self.entity_extractor.generate_entity_id(rel.source_label, rel.source_name)
            tgt_entity = self.entity_extractor.generate_entity_id(rel.target_label, rel.target_name)

            # Ensure both endpoint entities exist in Neo4j
            self.repo.create_or_update_entity(rel.source_label, {
                "id": src_entity,
                "name": rel.source_name,
                "is_synthetic": doc.is_synthetic
            })
            self.repo.create_or_update_entity(rel.target_label, {
                "id": tgt_entity,
                "name": rel.target_name,
                "is_synthetic": doc.is_synthetic
            })

            provenance_metadata = {
                "source_id": doc.source_id,
                "source_url": doc.url,
                "evidence_text": rel.evidence_text,
                "published_date": doc.published_date,
                "extraction_method": f"pipeline_llm_{doc.source_type}",
                "confidence": rel.confidence
            }

            self.repo.create_relationship(
                source_id=src_entity,
                source_label=rel.source_label,
                rel_type=rel.rel_type,
                target_id=tgt_entity,
                target_label=rel.target_label,
                provenance=provenance_metadata
            )

        logger.info(f"Ingestion Pipeline Complete for {doc.source_id}: {len(validation_result.accepted_relationships)} relationships inserted into Neo4j.")

        warnings = validation_result.warnings + [r["reason"] for r in validation_result.rejected_relationships[:5]]

        return IngestionResponse(
            source_id=doc.source_id,
            title=doc.title,
            chunks_count=len(chunks),
            entities_extracted=len(extracted_entities_map),
            relationships_extracted=len(raw_relationships),
            relationships_accepted=len(validation_result.accepted_relationships),
            relationships_rejected=len(validation_result.rejected_relationships),
            warnings=warnings,
            status="success"
        )
