"""
SigmaHQ Rule Repository & Review Workflow Service
Phase 12B Detection Engineering Implementation

Manages storage, retrieval, and analyst review state transitions
('draft' -> 'under_review' -> 'approved' / 'rejected') for Sigma rules,
with in-memory caching and optional Neo4j graph indexing.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional
from fastapi import HTTPException, status
import yaml

from app.core.logging import logger
from app.models.sigma import SigmaRule, ThreatMindProvenance
from app.services.stix.stix_graph_service import StixGraphService


class SigmaRepository:
    """
    In-memory and Neo4j-backed repository for Sigma rules with human review workflow.
    """

    def __init__(self, graph_service: Optional[StixGraphService] = None):
        self.graph_service = graph_service or StixGraphService()
        self._rules_by_id: Dict[str, SigmaRule] = {}

    def save_rule(self, rule: SigmaRule) -> SigmaRule:
        """
        Stores rule in memory and indexes in Neo4j if database is connected.
        """
        self._rules_by_id[rule.id] = rule

        # Attempt Neo4j indexing
        if self.graph_service.is_connected():
            try:
                cypher = """
                MERGE (r:SigmaRule {id: $id})
                SET r.title = $title,
                    r.status = $status,
                    r.level = $level,
                    r.technique_id = $technique_id,
                    r.review_status = $review_status,
                    r.raw_yaml = $raw_yaml,
                    r.updated_at = datetime()
                """
                tech_id = rule.threatmind_provenance.technique_id if rule.threatmind_provenance else None
                rev_status = rule.threatmind_provenance.review_status if rule.threatmind_provenance else "draft"
                params = {
                    "id": rule.id,
                    "title": rule.title,
                    "status": rule.status,
                    "level": rule.level,
                    "technique_id": tech_id,
                    "review_status": rev_status,
                    "raw_yaml": rule.raw_yaml or "",
                }
                self.graph_service.conn.query(cypher, params)
            except Exception as e:
                logger.warning(f"Could not index Sigma rule in Neo4j: {str(e)}")

        return rule

    def get_rule(self, rule_id: str) -> Optional[SigmaRule]:
        """
        Retrieves rule by ID from memory, or looks up in Neo4j.
        """
        if rule_id in self._rules_by_id:
            return self._rules_by_id[rule_id]

        if self.graph_service.is_connected():
            try:
                cypher = "MATCH (r:SigmaRule {id: $id}) RETURN r"
                res = self.graph_service.conn.query(cypher, {"id": rule_id})
                if res and res[0].get("r"):
                    props = dict(res[0]["r"])
                    raw_yaml = props.get("raw_yaml")
                    if raw_yaml:
                        parsed = yaml.safe_load(raw_yaml)
                        rule = SigmaRule.model_validate(parsed)
                        rule.raw_yaml = raw_yaml
                        self._rules_by_id[rule_id] = rule
                        return rule
            except Exception as e:
                logger.warning(f"Failed to fetch Sigma rule from Neo4j: {str(e)}")

        return None

    def list_rules(
        self,
        status_filter: Optional[str] = None,
        technique_id: Optional[str] = None,
        level: Optional[str] = None,
        review_status: Optional[str] = None,
    ) -> List[SigmaRule]:
        """
        Lists stored rules with optional filtering.
        """
        rules = list(self._rules_by_id.values())

        if status_filter:
            rules = [r for r in rules if r.status.lower() == status_filter.lower()]
        if level:
            rules = [r for r in rules if r.level.lower() == level.lower()]
        if technique_id:
            rules = [
                r for r in rules
                if r.threatmind_provenance and r.threatmind_provenance.technique_id
                and technique_id.lower() in r.threatmind_provenance.technique_id.lower()
            ]
        if review_status:
            rules = [
                r for r in rules
                if r.threatmind_provenance and r.threatmind_provenance.review_status.lower() == review_status.lower()
            ]

        return rules

    def update_review_status(
        self,
        rule_id: str,
        new_status: str,
        reviewer: str,
        notes: Optional[str] = None,
    ) -> SigmaRule:
        """
        Transitions rule review status ('draft', 'under_review', 'approved', 'rejected').
        """
        rule = self.get_rule(rule_id)
        if not rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Sigma rule with ID '{rule_id}' not found.",
            )

        valid_statuses = {"draft", "under_review", "approved", "rejected"}
        if new_status not in valid_statuses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid review status: '{new_status}'. Allowed: {sorted(valid_statuses)}.",
            )

        if not rule.threatmind_provenance:
            rule.threatmind_provenance = ThreatMindProvenance(
                rule_id=f"sigma-{rule.id}",
                review_status="draft",
            )

        prov = rule.threatmind_provenance
        prov.review_status = new_status  # type: ignore
        prov.reviewed_by = reviewer
        prov.reviewed_at = datetime.now(timezone.utc).isoformat()
        if notes:
            prov.review_notes.append(f"[{reviewer}] {notes}")

        # Update raw YAML
        try:
            parsed = yaml.safe_load(rule.raw_yaml) if rule.raw_yaml else rule.model_dump(exclude_none=True)
            parsed["threatmind_provenance"] = prov.model_dump(exclude_none=True)
            rule.raw_yaml = yaml.dump(parsed, sort_keys=False)
        except Exception:
            pass

        return self.save_rule(rule)
