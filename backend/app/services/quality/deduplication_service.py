"""
Multi-tier deduplication and duplicate intelligence suppression service.
Implements:
1. Exact cryptographic SHA-256 digest comparison.
2. 64-bit locality-sensitive SimHash with Hamming distance calculation.
3. Token-level Jaccard similarity for syndicated wire copy detection.
"""

import hashlib
import re
from typing import List, Set, Tuple
from app.models.quality import DuplicateDetectionResult, DuplicateType


class DeduplicationService:
    """
    Evaluates similarity between two threat intelligence reports or claim bodies,
    distinguishing exact copies, near duplicates, syndicated press wire reposts,
    and genuinely independent reporting.
    """

    @staticmethod
    def _normalize_text(text: str) -> str:
        return " ".join(text.strip().lower().split())

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        # Extract alphanumeric word tokens
        return re.findall(r"[a-z0-9_\-\.]+", text.lower())

    @staticmethod
    def compute_sha256(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @classmethod
    def compute_simhash64(cls, text: str) -> int:
        """
        Compute a 64-bit SimHash locality-sensitive fingerprint.
        """
        tokens = cls._tokenize(text)
        if not tokens:
            return 0

        v = [0] * 64
        for token in tokens:
            # Hash token to 64-bit integer using SHA-256 first 8 bytes
            h_bytes = hashlib.sha256(token.encode("utf-8")).digest()[:8]
            h_int = int.from_bytes(h_bytes, byteorder="big", signed=False)

            for i in range(64):
                bit = (h_int >> i) & 1
                if bit == 1:
                    v[i] += 1
                else:
                    v[i] -= 1

        fingerprint = 0
        for i in range(64):
            if v[i] > 0:
                fingerprint |= (1 << i)

        return fingerprint

    @staticmethod
    def hamming_distance(hash1: int, hash2: int) -> int:
        """Calculate bitwise Hamming distance between two 64-bit integers."""
        xor_val = hash1 ^ hash2
        return bin(xor_val).count("1")

    @classmethod
    def compute_jaccard_similarity(cls, text_a: str, text_b: str) -> float:
        """Calculate Jaccard similarity over word token sets."""
        tokens_a = set(cls._tokenize(text_a))
        tokens_b = set(cls._tokenize(text_b))
        if not tokens_a and not tokens_b:
            return 1.0
        if not tokens_a or not tokens_b:
            return 0.0
        intersection = tokens_a.intersection(tokens_b)
        union = tokens_a.union(tokens_b)
        return round(len(intersection) / len(union), 4)

    def analyze_pair(
        self,
        doc_a_id: str,
        text_a: str,
        doc_b_id: str,
        text_b: str,
        simhash_threshold: int = 6,
        jaccard_threshold: float = 0.80
    ) -> DuplicateDetectionResult:
        """
        Multi-tier deduplication check between two documents.
        """
        # Tier 1: Exact SHA-256
        sha_a = self.compute_sha256(text_a)
        sha_b = self.compute_sha256(text_b)
        is_exact = (sha_a == sha_b)

        if is_exact:
            return DuplicateDetectionResult(
                doc_a_id=doc_a_id,
                doc_b_id=doc_b_id,
                duplicate_type=DuplicateType.EXACT_DUPLICATE,
                exact_hash_match=True,
                simhash_distance=0,
                jaccard_similarity=1.0,
                suppression_recommended=True,
                explanation="Exact SHA-256 cryptographic match. Zero variance."
            )

        # Tier 2: 64-bit SimHash Hamming distance
        simhash_a = self.compute_simhash64(text_a)
        simhash_b = self.compute_simhash64(text_b)
        distance = self.hamming_distance(simhash_a, simhash_b)

        # Tier 3: Jaccard similarity
        jaccard = self.compute_jaccard_similarity(text_a, text_b)

        if distance <= simhash_threshold:
            return DuplicateDetectionResult(
                doc_a_id=doc_a_id,
                doc_b_id=doc_b_id,
                duplicate_type=DuplicateType.NEAR_DUPLICATE,
                exact_hash_match=False,
                simhash_distance=distance,
                jaccard_similarity=jaccard,
                suppression_recommended=True,
                explanation=f"Near duplicate detected with SimHash Hamming distance {distance} <= {simhash_threshold}."
            )

        if jaccard >= jaccard_threshold:
            return DuplicateDetectionResult(
                doc_a_id=doc_a_id,
                doc_b_id=doc_b_id,
                duplicate_type=DuplicateType.SYNDICATED_COPY,
                exact_hash_match=False,
                simhash_distance=distance,
                jaccard_similarity=jaccard,
                suppression_recommended=True,
                explanation=f"Syndicated wire copy detected with token Jaccard similarity {jaccard:.2f} >= {jaccard_threshold:.2f}."
            )

        return DuplicateDetectionResult(
            doc_a_id=doc_a_id,
            doc_b_id=doc_b_id,
            duplicate_type=DuplicateType.INDEPENDENT_REPORT,
            exact_hash_match=False,
            simhash_distance=distance,
            jaccard_similarity=jaccard,
            suppression_recommended=False,
            explanation=f"Independent report. SimHash distance {distance}, Jaccard {jaccard:.2f}."
        )
