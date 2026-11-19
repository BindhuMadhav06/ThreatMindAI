"""
Phase 14: Enterprise Asset Inventory Service.
Manages enterprise assets with strict multi-tenant isolation,
and parses CycloneDX and SPDX SBOM files into structured package inventories.
"""

import json
from typing import Dict, List, Optional
from app.models.organization import (
    Asset,
    AssetType,
    SBOMFormat,
    SBOMImportRequest,
    SBOMImportResponse,
    SoftwarePackage,
)


class AssetInventoryService:
    """
    Asset inventory repository ensuring cross-tenant data isolation
    and SBOM ingestion capabilities.
    """

    def __init__(self):
        self._assets: Dict[str, Asset] = {}

    def register_asset(self, asset: Asset) -> Asset:
        """Register or update an internal enterprise asset."""
        self._assets[asset.asset_id] = asset
        return asset

    def get_asset(self, asset_id: str, tenant_id: Optional[str] = None) -> Optional[Asset]:
        """
        Retrieve an asset with tenant isolation enforcement.
        If tenant_id is provided, access is forbidden across tenant boundaries.
        """
        asset = self._assets.get(asset_id)
        if not asset:
            return None
        if tenant_id and asset.tenant_id != tenant_id:
            return None
        return asset

    def list_assets(
        self,
        tenant_id: str,
        asset_type: Optional[AssetType] = None,
        criticality: Optional[str] = None
    ) -> List[Asset]:
        """List assets strictly scoped to the requesting tenant."""
        result = [a for a in self._assets.values() if a.tenant_id == tenant_id]
        if asset_type:
            result = [a for a in result if a.asset_type == asset_type]
        if criticality:
            result = [a for a in result if a.criticality == criticality]
        return result

    def import_sbom(self, request: SBOMImportRequest) -> SBOMImportResponse:
        """
        Ingest CycloneDX JSON or SPDX JSON SBOM into an asset's installed software list.
        Enforces tenant isolation on target asset.
        """
        asset = self.get_asset(request.target_asset_id, tenant_id=request.tenant_id)
        if not asset:
            return SBOMImportResponse(
                asset_id=request.target_asset_id,
                tenant_id=request.tenant_id,
                packages_imported=0,
                components=[],
                import_status="failed",
                warnings=[f"Target asset {request.target_asset_id} not found for tenant {request.tenant_id}."]
            )

        try:
            sbom_data = json.loads(request.sbom_content)
        except Exception as e:
            return SBOMImportResponse(
                asset_id=request.target_asset_id,
                tenant_id=request.tenant_id,
                packages_imported=0,
                components=[],
                import_status="failed",
                warnings=[f"Malformed SBOM JSON: {str(e)}"]
            )

        packages: List[SoftwarePackage] = []
        warnings: List[str] = []

        if request.sbom_format == SBOMFormat.CYCLONEDX_JSON:
            components = sbom_data.get("components", [])
            for c in components:
                name = c.get("name")
                version = c.get("version", "0.0.0")
                if not name:
                    continue
                cpe = c.get("cpe")
                vendor = c.get("publisher") or (c.get("supplier", {}).get("name") if isinstance(c.get("supplier"), dict) else None)
                lic_str = None
                licenses = c.get("licenses", [])
                if licenses and isinstance(licenses, list):
                    first_lic = licenses[0]
                    if isinstance(first_lic, dict):
                        lic_obj = first_lic.get("license", {})
                        lic_str = lic_obj.get("id") or lic_obj.get("name")

                packages.append(SoftwarePackage(
                    name=name,
                    version=version,
                    vendor=vendor,
                    cpe23=cpe,
                    license=lic_str
                ))

        elif request.sbom_format == SBOMFormat.SPDX_JSON:
            spdx_pkgs = sbom_data.get("packages", [])
            for p in spdx_pkgs:
                name = p.get("name")
                version = p.get("versionInfo", "0.0.0")
                if not name:
                    continue
                vendor = p.get("supplier") or p.get("originator")
                lic = p.get("licenseConcluded")
                cpe = None
                ext_refs = p.get("externalRefs", [])
                for ref in ext_refs:
                    if isinstance(ref, dict) and "cpe" in ref.get("referenceType", "").lower():
                        cpe = ref.get("referenceLocator")

                packages.append(SoftwarePackage(
                    name=name,
                    version=version,
                    vendor=vendor,
                    cpe23=cpe,
                    license=lic if lic != "NOASSERTION" else None
                ))
        else:
            return SBOMImportResponse(
                asset_id=request.target_asset_id,
                tenant_id=request.tenant_id,
                packages_imported=0,
                components=[],
                import_status="failed",
                warnings=[f"Unsupported SBOM format: {request.sbom_format}"]
            )

        # Deduplicate packages by (name.lower(), version)
        seen = set()
        deduped: List[SoftwarePackage] = []
        for pkg in packages:
            key = (pkg.name.lower(), pkg.version)
            if key not in seen:
                seen.add(key)
                deduped.append(pkg)

        # Merge with existing installed software
        existing_keys = {(p.name.lower(), p.version) for p in asset.installed_software}
        for pkg in deduped:
            if (pkg.name.lower(), pkg.version) not in existing_keys:
                asset.installed_software.append(pkg)

        asset.import_provenance = f"SBOM_{request.sbom_format.value}"

        return SBOMImportResponse(
            asset_id=asset.asset_id,
            tenant_id=asset.tenant_id,
            packages_imported=len(deduped),
            components=deduped,
            import_status="success",
            warnings=warnings
        )
