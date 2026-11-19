"""
SigmaHQ Detection Rule Validation Service
Phase 12B Detection Engineering Implementation

Integrates pySigma v2.1.0 to enforce strict specification conformance,
logsource consistency, condition syntax verification, and ATT&CK tag format.
Guarantees zero detection condition schema pollution from sidecar metadata.
"""

import re
from typing import Any, Dict, List, Optional
import yaml
from sigma.rule import SigmaRule as PySigmaRule
from app.core.logging import logger


class SigmaValidationService:
    """
    Validates SigmaHQ v2.1.0 rules and ThreatMind sidecar provenance.
    """

    REQUIRED_TOP_LEVEL_FIELDS = [
        "title",
        "id",
        "status",
        "description",
        "logsource",
        "detection",
        "level",
    ]

    VALID_STATUSES = {"experimental", "test", "stable", "deprecated", "unsupported"}
    VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}

    def validate_yaml(self, yaml_content: str) -> Dict[str, Any]:
        """
        Validates raw Sigma YAML string using pySigma and custom validation rules.
        """
        errors: List[str] = []
        warnings: List[str] = []
        parsed_dict: Optional[Dict[str, Any]] = None

        # 1. Parse YAML
        try:
            parsed_dict = yaml.safe_load(yaml_content)
        except Exception as e:
            return {
                "is_valid": False,
                "errors": [f"YAML syntax error: {str(e)}"],
                "warnings": [],
                "parsed_rule": None,
            }

        if not isinstance(parsed_dict, dict):
            return {
                "is_valid": False,
                "errors": ["Sigma rule YAML must define a dictionary root object."],
                "warnings": [],
                "parsed_rule": None,
            }

        # 2. Extract and Validate Sidecar Provenance (Ensure NO pollution in detection block)
        provenance = parsed_dict.get("threatmind_provenance")
        if provenance:
            if not isinstance(provenance, dict):
                errors.append("'threatmind_provenance' must be a mapping object if provided.")
            else:
                review_status = provenance.get("review_status")
                if review_status and review_status not in ("draft", "under_review", "approved", "rejected"):
                    errors.append(f"Invalid review_status in provenance: '{review_status}'.")

        # 3. Check Required Top-Level Fields
        for field in self.REQUIRED_TOP_LEVEL_FIELDS:
            if field not in parsed_dict or parsed_dict[field] is None:
                errors.append(f"Missing required Sigma field: '{field}'.")

        # 4. Check Status and Level values
        status_val = str(parsed_dict.get("status", "")).lower()
        if status_val and status_val not in self.VALID_STATUSES:
            errors.append(f"Invalid status value: '{status_val}'. Must be one of {sorted(self.VALID_STATUSES)}.")

        level_val = str(parsed_dict.get("level", "")).lower()
        if level_val and level_val not in self.VALID_LEVELS:
            errors.append(f"Invalid level value: '{level_val}'. Must be one of {sorted(self.VALID_LEVELS)}.")

        # 5. Check Logsource
        logsource = parsed_dict.get("logsource")
        if isinstance(logsource, dict):
            if not any(logsource.get(k) for k in ("category", "product", "service")):
                warnings.append("Logsource should specify at least one of 'category', 'product', or 'service'.")
        elif "logsource" in parsed_dict:
            errors.append("'logsource' must be a dictionary object.")

        # 6. Check Detection Block (Enforce Zero Schema Pollution)
        detection = parsed_dict.get("detection")
        if isinstance(detection, dict):
            # Enforce condition field exists
            if "condition" not in detection:
                errors.append("Detection block is missing required 'condition' property.")
            else:
                condition_str = str(detection["condition"])
                # Ensure no ThreatMind metadata leaked into condition
                if "threatmind" in condition_str.lower() or "provenance" in condition_str.lower():
                    errors.append("Detection condition contains ThreatMind metadata: schema pollution detected.")

            # Ensure referenced selections exist in detection
            condition = str(detection.get("condition", ""))
            tokens = re.findall(r"\b[a-zA-Z0-9_]+\b", condition)
            keywords = {"and", "or", "not", "all", "of", "them", "1", "min"}
            for token in tokens:
                if token.lower() not in keywords and not token.isdigit():
                    if token not in detection:
                        warnings.append(f"Condition references identifier '{token}' not explicitly defined in detection block.")
        elif "detection" in parsed_dict:
            errors.append("'detection' must be a dictionary object.")

        # 7. Check ATT&CK Tags
        tags = parsed_dict.get("tags", [])
        if isinstance(tags, list):
            for tag in tags:
                tag_str = str(tag).lower()
                if not (tag_str.startswith("attack.") or tag_str.startswith("cve.") or tag_str.startswith("detection.")):
                    warnings.append(f"Non-standard tag format: '{tag}'. Expected 'attack.<tactic|technique>' prefix.")

        # 8. pySigma Parser Validation
        # pySigma expects a standard rule without non-standard top-level keys like threatmind_provenance
        # So we create a clean copy for pySigma validation
        clean_rule_dict = {k: v for k, v in parsed_dict.items() if k != "threatmind_provenance"}
        try:
            clean_yaml = yaml.dump(clean_rule_dict)
            py_rule = PySigmaRule.from_yaml(clean_yaml)
            if not py_rule.title:
                errors.append("pySigma could not parse a valid title.")
        except Exception as e:
            errors.append(f"pySigma validation error: {str(e)}")

        is_valid = len(errors) == 0

        return {
            "is_valid": is_valid,
            "errors": errors,
            "warnings": warnings,
            "parsed_rule": parsed_dict if is_valid else None,
        }
