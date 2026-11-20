"""
Phase 14: Enterprise Asset Inventory Service.
Manages enterprise assets with strict multi-tenant isolation,
durable SQLite persistence (surviving process restarts and multi-worker execution),
and parses CycloneDX and SPDX SBOM files into structured package inventories.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
import sqlite3
import threading
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
    Durable Asset Inventory Repository backed by SQLite in WAL mode.
    Ensures strict cross-tenant data isolation, SBOM package ingestion,
    and process-restart persistence.
    """

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
            self.db_path = os.path.join(base_dir, "data", "organization", "inventory.db")
        else:
            self.db_path = db_path

        if self.db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)

        self._lock = threading.Lock()
        self._init_db()

    @contextmanager
    def _connection(self):
        conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        if self.db_path != ":memory:":
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._lock:
            with self._connection() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS enterprise_assets (
                        asset_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        name TEXT NOT NULL,
                        asset_type TEXT NOT NULL,
                        criticality TEXT NOT NULL,
                        external_exposure INTEGER NOT NULL DEFAULT 0,
                        raw_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_tenant ON enterprise_assets(tenant_id);")
                conn.commit()

    def register_asset(self, asset: Asset) -> Asset:
        """Register or update an internal enterprise asset in durable storage."""
        now_iso = datetime.now(timezone.utc).isoformat()
        asset_json = asset.model_dump_json()

        with self._lock:
            with self._connection() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO enterprise_assets (
                        asset_id, tenant_id, name, asset_type, criticality,
                        external_exposure, raw_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        asset.asset_id,
                        asset.tenant_id,
                        asset.name,
                        asset.asset_type.value if hasattr(asset.asset_type, "value") else str(asset.asset_type),
                        asset.criticality.value if hasattr(asset.criticality, "value") else str(asset.criticality),
                        1 if asset.external_exposure else 0,
                        asset_json,
                        now_iso,
                        now_iso,
                    ),
                )
                conn.commit()
        return asset

    def get_asset(self, asset_id: str, tenant_id: Optional[str] = None) -> Optional[Asset]:
        """
        Retrieve an asset with tenant isolation enforcement from durable storage.
        If tenant_id is provided, cross-tenant access is strictly denied (returns None).
        """
        with self._lock:
            with self._connection() as conn:
                if tenant_id:
                    cur = conn.execute(
                        "SELECT raw_json FROM enterprise_assets WHERE asset_id = ? AND tenant_id = ?",
                        (asset_id, tenant_id),
                    )
                else:
                    cur = conn.execute(
                        "SELECT raw_json FROM enterprise_assets WHERE asset_id = ?",
                        (asset_id,),
                    )
                row = cur.fetchone()
                if not row:
                    return None
                return Asset.model_validate_json(row["raw_json"])

    def list_assets(
        self,
        tenant_id: str,
        asset_type: Optional[AssetType] = None,
        criticality: Optional[str] = None,
    ) -> List[Asset]:
        """List assets strictly scoped to the requesting tenant."""
        with self._lock:
            with self._connection() as conn:
                cur = conn.execute(
                    "SELECT raw_json FROM enterprise_assets WHERE tenant_id = ?",
                    (tenant_id,),
                )
                rows = cur.fetchall()

        assets = [Asset.model_validate_json(r["raw_json"]) for r in rows]
        if asset_type:
            val = asset_type.value if hasattr(asset_type, "value") else asset_type
            assets = [a for a in assets if (a.asset_type.value if hasattr(a.asset_type, "value") else a.asset_type) == val]
        if criticality:
            crit_str = criticality.value if hasattr(criticality, "value") else str(criticality).lower()
            assets = [a for a in assets if (a.criticality.value if hasattr(a.criticality, "value") else str(a.criticality).lower()) == crit_str]
        return assets

    def delete_asset(self, asset_id: str, tenant_id: str) -> bool:
        """Delete an asset strictly within tenant scope."""
        with self._lock:
            with self._connection() as conn:
                cur = conn.execute(
                    "DELETE FROM enterprise_assets WHERE asset_id = ? AND tenant_id = ?",
                    (asset_id, tenant_id),
                )
                conn.commit()
                return cur.rowcount > 0

    def clear(self) -> None:
        """Utility for test suite reset."""
        with self._lock:
            with self._connection() as conn:
                conn.execute("DELETE FROM enterprise_assets")
                conn.commit()

    def import_sbom(self, request: SBOMImportRequest) -> SBOMImportResponse:
        """
        Ingest CycloneDX JSON or SPDX JSON SBOM into an asset's installed software list.
        Enforces tenant isolation on target asset and persists updates to SQLite.
        """
        asset = self.get_asset(request.target_asset_id, tenant_id=request.tenant_id)
        if not asset:
            return SBOMImportResponse(
                asset_id=request.target_asset_id,
                tenant_id=request.tenant_id,
                packages_imported=0,
                components=[],
                import_status="failed",
                warnings=[f"Target asset {request.target_asset_id} not found for tenant {request.tenant_id}."],
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
                warnings=[f"Malformed SBOM JSON: {str(e)}"],
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
                    license=lic_str,
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
                    license=lic if lic != "NOASSERTION" else None,
                ))
        else:
            return SBOMImportResponse(
                asset_id=request.target_asset_id,
                tenant_id=request.tenant_id,
                packages_imported=0,
                components=[],
                import_status="failed",
                warnings=[f"Unsupported SBOM format: {request.sbom_format}"],
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

        # Persist updated asset to durable SQLite storage
        self.register_asset(asset)

        return SBOMImportResponse(
            asset_id=asset.asset_id,
            tenant_id=asset.tenant_id,
            packages_imported=len(deduped),
            components=deduped,
            import_status="success",
            warnings=warnings,
        )
