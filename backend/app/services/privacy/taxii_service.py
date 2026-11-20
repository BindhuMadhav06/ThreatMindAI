"""
Phase 16: TAXII 2.1 Federation & Collaborative Sharing Service.
Implements standards-based TAXII 2.1 collections, bounded object querying,
untrusted external ingestion tagging with confidence discounts (0.35 penalty),
persistent SQLite backing across process restarts, and cryptographically signed
tombstone retraction ledgers.
"""

from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional
import uuid

from app.models.privacy import (
    CollaborationRetractionRequest,
    SharingScope,
    TAXIICollection,
    TAXIISharingRecord,
    TLPMarking,
)
from app.services.privacy.anonymization_service import AnonymizationService
from app.services.privacy.sharing_policy_service import SharingPolicyService
from app.core.logging import logger


class TAXIIFederationService:
    """
    Manages TAXII 2.1 collections, inbound/outbound federation,
    persistent database storage, and cryptographically signed tombstone retractions.
    """

    def __init__(
        self,
        db_path: Optional[Path] = None,
        policy_service: Optional[SharingPolicyService] = None,
        anonymization_service: Optional[AnonymizationService] = None
    ):
        self.policy_service = policy_service or SharingPolicyService()
        self.anonymizer = anonymization_service or AnonymizationService()

        # Database initialization
        storage_dir = Path(__file__).resolve().parents[4] / "data" / "federation"
        storage_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = str(db_path or (storage_dir / "taxii_store.db"))
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initializes SQLite schema and seeds standard TAXII 2.1 collections."""
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
            CREATE TABLE IF NOT EXISTS taxii_collections (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                alias TEXT,
                can_read INTEGER NOT NULL,
                can_write INTEGER NOT NULL
            );
            """)
            cur.execute("""
            CREATE TABLE IF NOT EXISTS sharing_records (
                record_id TEXT PRIMARY KEY,
                collection_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                object_id TEXT NOT NULL,
                object_type TEXT NOT NULL,
                tlp_marking TEXT NOT NULL,
                sharing_scope TEXT NOT NULL,
                status TEXT NOT NULL,
                retraction_reason TEXT,
                retracted_at TEXT,
                superseded_by TEXT,
                tombstone_signature TEXT,
                created_at TEXT NOT NULL
            );
            """)
            cur.execute("""
            CREATE TABLE IF NOT EXISTS collection_objects (
                id TEXT PRIMARY KEY,
                collection_id TEXT NOT NULL,
                object_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                date_added TEXT NOT NULL
            );
            """)
            cur.execute("""
            CREATE TABLE IF NOT EXISTS tombstone_ledger (
                tombstone_id TEXT PRIMARY KEY,
                record_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                object_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                payload_digest TEXT NOT NULL,
                created_at TEXT NOT NULL,
                reason TEXT
            );
            """)

            # Seed default standard collections if missing
            cur.execute("SELECT COUNT(*) FROM taxii_collections;")
            if cur.fetchone()[0] == 0:
                cur.execute("""
                INSERT INTO taxii_collections (id, title, description, alias, can_read, can_write)
                VALUES 
                ('collection_isac_shared', 'Community ISAC Threat Feed', 'Verified cross-organization threat intelligence sharing channel.', 'isac-feed', 1, 1),
                ('collection_public_feed', 'Public CTI Observable Exchange', 'Open source indicators and community disclosures.', 'public-observables', 1, 0);
                """)
            conn.commit()

    def list_collections(self) -> List[TAXIICollection]:
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, title, description, alias, can_read, can_write FROM taxii_collections")
            rows = cur.fetchall()
            return [
                TAXIICollection(
                    id=row["id"],
                    title=row["title"],
                    description=row["description"],
                    alias=row["alias"],
                    can_read=bool(row["can_read"]),
                    can_write=bool(row["can_write"])
                )
                for row in rows
            ]

    def get_collection(self, collection_id: str) -> Optional[TAXIICollection]:
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, title, description, alias, can_read, can_write FROM taxii_collections WHERE id = ?", (collection_id,))
            row = cur.fetchone()
            if not row:
                return None
            return TAXIICollection(
                id=row["id"],
                title=row["title"],
                description=row["description"],
                alias=row["alias"],
                can_read=bool(row["can_read"]),
                can_write=bool(row["can_write"])
            )

    def publish_object_to_collection(
        self,
        collection_id: str,
        tenant_id: str,
        obj: Dict[str, Any],
        tlp_marking: TLPMarking = TLPMarking.TLP_GREEN,
        recipient_id: Optional[str] = "isac_member_verified"
    ) -> TAXIISharingRecord:
        """
        Publish intelligence object into TAXII collection with policy authorization
        and recursive anonymization of internal identifiers.
        Persists both record and object into the SQLite database.
        """
        col = self.get_collection(collection_id)
        if not col:
            raise KeyError(f"TAXII collection '{collection_id}' not found.")
        if not col.can_write:
            raise PermissionError(f"Collection '{collection_id}' is read-only.")

        # Check Sharing Policy (Blocks TLP:RED from external scopes)
        is_auth, reason = self.policy_service.evaluate_export_authorization(
            tenant_id=tenant_id,
            object_tlp=tlp_marking,
            requested_scope=SharingScope.COMMUNITY_ISAC,
            recipient_id=recipient_id,
            contains_internal_identifiers=True
        )
        if not is_auth:
            raise PermissionError(reason)

        # Recursively anonymize private internal identifiers, credentials, and hostnames
        sanitized_obj = self.anonymizer.sanitize_recursive(obj, tenant_id)

        record_id = f"share_{uuid.uuid4().hex[:12]}"
        now_str = datetime.now(timezone.utc).isoformat()
        object_id = sanitized_obj.get("id", f"indicator--{uuid.uuid4()}")
        object_type = sanitized_obj.get("type", "indicator")

        record = TAXIISharingRecord(
            record_id=record_id,
            collection_id=collection_id,
            tenant_id=tenant_id,
            object_id=object_id,
            object_type=object_type,
            tlp_marking=tlp_marking,
            sharing_scope=SharingScope.COMMUNITY_ISAC,
            status="ACTIVE"
        )

        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
            INSERT INTO sharing_records 
            (record_id, collection_id, tenant_id, object_id, object_type, tlp_marking, sharing_scope, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (record_id, collection_id, tenant_id, object_id, object_type, tlp_marking.value, SharingScope.COMMUNITY_ISAC.value, "ACTIVE", now_str))

            entry_id = f"entry_{uuid.uuid4().hex[:12]}"
            cur.execute("""
            INSERT INTO collection_objects (id, collection_id, object_id, payload_json, date_added)
            VALUES (?, ?, ?, ?, ?)
            """, (entry_id, collection_id, object_id, json.dumps(sanitized_obj), now_str))
            conn.commit()

        return record

    def get_collection_objects(
        self,
        collection_id: str,
        max_limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Retrieve bounded objects from persistent collection storage."""
        col = self.get_collection(collection_id)
        if not col:
            raise KeyError(f"TAXII collection '{collection_id}' not found.")

        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
            SELECT payload_json FROM collection_objects
            WHERE collection_id = ?
            ORDER BY date_added DESC
            LIMIT ?
            """, (collection_id, max_limit))
            rows = cur.fetchall()
            return [json.loads(row["payload_json"]) for row in rows]

    def get_collection_manifest(
        self,
        collection_id: str,
        max_limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Retrieve TAXII 2.1 manifest entries for a collection."""
        col = self.get_collection(collection_id)
        if not col:
            raise KeyError(f"TAXII collection '{collection_id}' not found.")

        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
            SELECT object_id, date_added, payload_json FROM collection_objects
            WHERE collection_id = ?
            ORDER BY date_added DESC
            LIMIT ?
            """, (collection_id, max_limit))
            rows = cur.fetchall()
            manifest = []
            for r in rows:
                obj = json.loads(r["payload_json"])
                manifest.append({
                    "id": r["object_id"],
                    "date_added": r["date_added"],
                    "version": obj.get("modified", r["date_added"]),
                    "media_types": ["application/stix+json;version=2.1"]
                })
            return manifest

    def ingest_external_taxii_object(
        self,
        collection_id: str,
        obj: Dict[str, Any],
        source_feed_name: str = "External_TAXII_Feed"
    ) -> Dict[str, Any]:
        """
        Ingest external object received via TAXII federation.
        INVARIANTS:
        1. Tagged strictly as UNTRUSTED_EXTERNAL data.
        2. Applies a 0.35 confidence penalty to mitigate poison claims.
        3. Persisted into the persistent collection object store.
        """
        col = self.get_collection(collection_id)
        if not col:
            raise KeyError(f"TAXII collection '{collection_id}' not found.")

        tagged_obj = dict(obj)
        now_str = datetime.now(timezone.utc).isoformat()

        # Apply confidence discount (0.35 penalty)
        if "confidence" in tagged_obj and isinstance(tagged_obj["confidence"], (int, float)):
            original_conf = float(tagged_obj["confidence"])
            discounted_conf = max(0.0, round(original_conf * 0.65, 2))
            tagged_obj["confidence"] = discounted_conf
            tagged_obj["original_confidence"] = original_conf

        tagged_obj["threatmind_provenance"] = {
            "source_type": "UNTRUSTED_EXTERNAL_TAXII",
            "source_feed": source_feed_name,
            "collection_id": collection_id,
            "confidence_discount": 0.35,
            "ingested_at": now_str,
            "validation_status": "unverified_external"
        }

        object_id = tagged_obj.get("id", f"indicator--{uuid.uuid4()}")
        entry_id = f"entry_ext_{uuid.uuid4().hex[:12]}"

        # Persist into collection storage
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
            INSERT INTO collection_objects (id, collection_id, object_id, payload_json, date_added)
            VALUES (?, ?, ?, ?, ?)
            """, (entry_id, collection_id, object_id, json.dumps(tagged_obj), now_str))
            conn.commit()

        return tagged_obj

    def retract_intelligence(self, req: CollaborationRetractionRequest) -> TAXIISharingRecord:
        """
        Retract a previously shared intelligence object.
        Generates and stores an authenticated cryptographic HMAC-SHA256 tombstone signature.
        Preserves complete historical record in tombstone status.
        """
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
            SELECT record_id, collection_id, tenant_id, object_id, object_type, tlp_marking,
                   sharing_scope, status, retraction_reason, retracted_at, superseded_by, tombstone_signature
            FROM sharing_records WHERE record_id = ?
            """, (req.record_id,))
            row = cur.fetchone()
            if not row:
                raise KeyError(f"Sharing record '{req.record_id}' not found.")

            if row["tenant_id"] != req.tenant_id and req.tenant_id != "admin":
                raise PermissionError(f"Access denied: Tenant mismatch on intelligence retraction.")

            now_str = datetime.now(timezone.utc).isoformat()
            new_status = "SUPERSEDED" if req.superseding_object_id else "RETRACTED"

            # Cryptographically sign the tombstone
            tenant_salt = self.anonymizer.get_or_create_tenant_salt(row["tenant_id"])
            tombstone_payload = f"{req.record_id}:{row['object_id']}:{row['tenant_id']}:{req.reason}:{now_str}"
            payload_digest = hashlib.sha256(tombstone_payload.encode("utf-8")).hexdigest()
            tombstone_sig = hmac.new(tenant_salt, payload_digest.encode("utf-8"), hashlib.sha256).hexdigest()

            cur.execute("""
            UPDATE sharing_records
            SET status = ?, retraction_reason = ?, retracted_at = ?, superseded_by = ?, tombstone_signature = ?
            WHERE record_id = ?
            """, (new_status, req.reason, now_str, req.superseding_object_id, tombstone_sig, req.record_id))

            tombstone_id = f"tomb_{uuid.uuid4().hex[:12]}"
            cur.execute("""
            INSERT INTO tombstone_ledger 
            (tombstone_id, record_id, tenant_id, object_id, signature, payload_digest, created_at, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (tombstone_id, req.record_id, row["tenant_id"], row["object_id"], tombstone_sig, payload_digest, now_str, req.reason))
            conn.commit()

            return TAXIISharingRecord(
                record_id=row["record_id"],
                collection_id=row["collection_id"],
                tenant_id=row["tenant_id"],
                object_id=row["object_id"],
                object_type=row["object_type"],
                tlp_marking=TLPMarking(row["tlp_marking"]),
                sharing_scope=SharingScope(row["sharing_scope"]),
                status=new_status,
                retraction_reason=req.reason,
                retracted_at=now_str,
                superseded_by=req.superseding_object_id
            )

    def verify_tombstone(self, record_id: str) -> Dict[str, Any]:
        """Verifies the cryptographic integrity of a retracted object's tombstone signature."""
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
            SELECT record_id, tenant_id, object_id, signature, payload_digest, created_at, reason
            FROM tombstone_ledger WHERE record_id = ?
            """, (record_id,))
            row = cur.fetchone()
            if not row:
                return {"verified": False, "reason": "No tombstone signature found for record."}

            tenant_salt = self.anonymizer.get_or_create_tenant_salt(row["tenant_id"])
            expected_sig = hmac.new(tenant_salt, row["payload_digest"].encode("utf-8"), hashlib.sha256).hexdigest()
            is_valid = hmac.compare_digest(expected_sig, row["signature"])
            return {
                "verified": is_valid,
                "record_id": record_id,
                "signature": row["signature"],
                "created_at": row["created_at"],
                "reason": row["reason"]
            }
