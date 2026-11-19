"""
STIX 2.1 Independent Validation Service
Phase 12A Hardening (A6: Independent stix2-validator Integration)

Wraps OASIS stix2-validator (v3.3.2) to perform standards-compliant
validation of exported bundles, SDOs, and SROs.
"""

import json
from typing import Any, Dict, List, Optional
import stix2validator
from stix2validator import ValidationOptions
from app.core.logging import logger


class StixValidatorService:
    """
    Provides independent STIX 2.1 conformance validation using OASIS stix2-validator.
    """

    def __init__(self, strict: bool = False):
        self.strict = strict
        # Configure validation options for STIX 2.1
        self.options = ValidationOptions(
            version="2.1",
            strict=strict,
        )

    def validate_bundle_string(self, bundle_str: str) -> Dict[str, Any]:
        """
        Validates a STIX 2.1 bundle serialized as a JSON string.
        Returns a dictionary with is_valid, errors, and warnings.
        """
        try:
            results = stix2validator.validate_string(bundle_str, self.options)
            is_valid = getattr(results, "is_valid", False)
            errors: List[str] = []
            warnings: List[str] = []

            if hasattr(results, "errors"):
                for e in results.errors:
                    errors.append(getattr(e, "message", str(e)))
            if hasattr(results, "warnings"):
                for w in results.warnings:
                    warnings.append(getattr(w, "message", str(w)))

            return {
                "is_valid": is_valid,
                "errors": errors,
                "warnings": warnings,
            }
        except Exception as e:
            logger.error(f"STIX validator execution failed: {str(e)}", exc_info=True)
            return {
                "is_valid": False,
                "errors": [f"Validator exception: {str(e)}"],
                "warnings": [],
            }

    def validate_bundle_dict(self, bundle_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validates a STIX 2.1 bundle object represented as a Python dictionary.
        """
        try:
            bundle_str = json.dumps(bundle_dict)
            return self.validate_bundle_string(bundle_str)
        except Exception as e:
            return {
                "is_valid": False,
                "errors": [f"JSON serialization error prior to validation: {str(e)}"],
                "warnings": [],
            }
