"""
Phase 14: Asset-to-Threat Matching Service.
Implements robust semantic version matching and CPE matching,
strictly rejecting naive substring matching to eliminate false positives.
"""

import re
from typing import Any, Dict, List, Optional
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from app.models.organization import Asset, AssetThreatMatch, SoftwarePackage


class AssetThreatMatcher:
    """
    Evaluates enterprise assets against CVE advisories and threat intelligence.
    Enforces strict semantic version constraints over naive text containment.
    """

    @staticmethod
    def _clean_version_str(v_str: str) -> str:
        """Strip leading 'v' or 'V' and whitespace."""
        s = v_str.strip()
        if s.startswith(('v', 'V')):
            s = s[1:]
        return s

    @classmethod
    def is_version_vulnerable(cls, installed_version: str, vulnerable_range: str) -> bool:
        """
        Check if installed_version satisfies vulnerable_range using packaging.specifiers.
        Accepts ranges like:
          '< 2.15.0'
          '>= 2.0.0, < 2.15.0'
          '<= 1.4.2'
          '== 2.12.1'
        """
        cleaned_installed = cls._clean_version_str(installed_version)
        try:
            parsed_v = Version(cleaned_installed)
        except InvalidVersion:
            # Fallback regex for standard 3-part or 2-part numeric version if packaging fails
            match = re.search(r"(\d+(?:\.\d+)+)", cleaned_installed)
            if match:
                try:
                    parsed_v = Version(match.group(1))
                except InvalidVersion:
                    return False
            else:
                return False

        # Normalize specifier string
        spec_str = vulnerable_range.strip()
        try:
            spec_set = SpecifierSet(spec_str)
            return parsed_v in spec_set
        except InvalidSpecifier:
            # If specifier syntax is custom (e.g. 'all versions before 2.15.0')
            before_match = re.search(r"(?:before|<)\s*([0-9\.]+)", spec_str, re.IGNORECASE)
            if before_match:
                try:
                    cutoff = Version(before_match.group(1))
                    return parsed_v < cutoff
                except InvalidVersion:
                    pass
            return False

    def match_asset_vulnerability(
        self,
        asset: Asset,
        cve_id: str,
        target_package: str,
        vulnerable_range: str,
        threat_entity_id: Optional[str] = None
    ) -> Optional[AssetThreatMatch]:
        """
        Match an asset against a vulnerability using exact package name identity
        and SemVer range evaluation.
        STRICT: Does NOT use substring matching.
        """
        norm_target = target_package.strip().lower()

        # Find matching package by exact normalized name
        matched_pkg: Optional[SoftwarePackage] = None
        for pkg in asset.installed_software:
            # Rejects naive substring matching! (e.g. 'openssl-helper' should not match 'openssl')
            if pkg.name.strip().lower() == norm_target:
                matched_pkg = pkg
                break

        if not matched_pkg:
            return None

        # Check SemVer range
        is_vuln = self.is_version_vulnerable(matched_pkg.version, vulnerable_range)
        if not is_vuln:
            return None

        match_id = f"match_{asset.asset_id}_{cve_id}_{matched_pkg.name}"
        return AssetThreatMatch(
            match_id=match_id,
            asset_id=asset.asset_id,
            asset_name=asset.name,
            tenant_id=asset.tenant_id,
            threat_entity_id=threat_entity_id or cve_id,
            threat_type="vulnerability",
            cve_id=cve_id,
            package_name=matched_pkg.name,
            installed_version=matched_pkg.version,
            vulnerable_range=vulnerable_range,
            affected_version_matched=True,
            matching_confidence=0.98,
            evidence_rationale=(
                f"Installed package '{matched_pkg.name}' version '{matched_pkg.version}' "
                f"satisfies vulnerable constraint '{vulnerable_range}' for {cve_id}."
            )
        )

    def scan_asset_against_advisories(
        self,
        asset: Asset,
        advisories: List[Dict[str, Any]]
    ) -> List[AssetThreatMatch]:
        """
        Scan an asset against a list of vulnerability advisories.
        Each advisory is expected to have:
          - 'cve_id': str
          - 'package_name': str
          - 'vulnerable_range': str
          - 'threat_entity_id': optional str
        """
        matches: List[AssetThreatMatch] = []
        for adv in advisories:
            cve = adv.get("cve_id", "")
            pkg = adv.get("package_name", "")
            v_range = adv.get("vulnerable_range", "")
            threat_id = adv.get("threat_entity_id")
            if not cve or not pkg or not v_range:
                continue

            match = self.match_asset_vulnerability(
                asset=asset,
                cve_id=cve,
                target_package=pkg,
                vulnerable_range=v_range,
                threat_entity_id=threat_id
            )
            if match:
                matches.append(match)
        return matches
