from typing import List, Dict, Any, Tuple
from app.models.reasoning import ReasoningStep, PathValidationResult
from app.services.graph.schema_manager import PRIMARY_NODE_LABELS, SUPPORTED_RELATIONSHIPS
from app.core.logging import logger

class PathValidator:
    """
    Strict Path Validation Engine.
    Validates each reasoning step and multi-hop path independently against
    schema rules, evidence existence, endpoint integrity, and acyclic constraints.
    """

    @classmethod
    def validate_step(cls, step: ReasoningStep) -> Tuple[bool, List[str]]:
        notes: List[str] = []
        is_valid = True

        allowed_labels = {l.lower() for l in PRIMARY_NODE_LABELS}
        allowed_rels = {r.lower() for r in SUPPORTED_RELATIONSHIPS}

        # 1. Endpoint Integrity Check
        if not step.source_id or not step.target_id:
            notes.append("REJECTED: Source or target entity ID is empty.")
            is_valid = False

        if step.source_label.lower() not in allowed_labels:
            notes.append(f"REJECTED: Invalid source label '{step.source_label}'.")
            is_valid = False

        if step.target_label.lower() not in allowed_labels:
            notes.append(f"REJECTED: Invalid target label '{step.target_label}'.")
            is_valid = False

        # 2. Relationship Type Whitelist Check
        if step.rel_type.lower() not in allowed_rels:
            notes.append(f"REJECTED: Disallowed relationship type '{step.rel_type}'.")
            is_valid = False

        # 3. Mandatory Evidence & Provenance Check
        if not step.evidence_records:
            notes.append("REJECTED: No evidence records attached to this relationship.")
            is_valid = False
        else:
            for ev in step.evidence_records:
                if not ev.evidence_text or not ev.evidence_text.strip():
                    notes.append("REJECTED: Evidence record has empty evidence_text.")
                    is_valid = False
                if not ev.source_id or not ev.source_id.strip():
                    notes.append("REJECTED: Evidence record has empty source_id.")
                    is_valid = False

        return is_valid, notes

    @classmethod
    def validate_path(cls, steps: List[ReasoningStep]) -> PathValidationResult:
        if not steps:
            return PathValidationResult(
                is_valid=False,
                validation_status="rejected",
                reasons=["Path contains 0 steps."],
                steps_evaluated=0,
                valid_steps_count=0
            )

        all_reasons: List[str] = []
        valid_steps = 0
        seen_nodes = set()

        # Check for cycles
        seen_nodes.add(steps[0].source_id)
        for i, step in enumerate(steps):
            step_valid, notes = cls.validate_step(step)
            step.is_valid = step_valid
            step.validation_notes = notes

            if step_valid:
                valid_steps += 1
            else:
                all_reasons.extend([f"Step {step.step_number} ({step.source_name} -[{step.rel_type}]-> {step.target_name}): {note}" for note in notes])

            # Endpoint continuity check: step i's target must match step i+1's source
            if i > 0 and step.source_id != steps[i - 1].target_id:
                all_reasons.append(f"Step {step.step_number} source '{step.source_id}' does not connect to previous step target '{steps[i - 1].target_id}'.")

            # Cycle detection
            if step.target_id in seen_nodes:
                all_reasons.append(f"Cycle detected: node '{step.target_id}' is visited more than once in this path.")
            else:
                seen_nodes.add(step.target_id)

        if valid_steps == len(steps) and not any("Cycle detected" in r or "does not connect" in r for r in all_reasons):
            return PathValidationResult(
                is_valid=True,
                validation_status="accepted",
                reasons=[],
                steps_evaluated=len(steps),
                valid_steps_count=valid_steps
            )
        elif valid_steps > 0:
            return PathValidationResult(
                is_valid=False,
                validation_status="partial",
                reasons=all_reasons,
                steps_evaluated=len(steps),
                valid_steps_count=valid_steps
            )
        else:
            return PathValidationResult(
                is_valid=False,
                validation_status="rejected",
                reasons=all_reasons,
                steps_evaluated=len(steps),
                valid_steps_count=0
            )

path_validator = PathValidator()
