import os
import json
import re
from typing import List, Dict, Any, Optional
from app.services.retrieval.entity_resolver import entity_resolver
from app.services.graph.repository import graph_repository
from app.services.answering.answer_generator import AnswerGenerator
from app.services.answering.prompt_builder import ABSTENTION_PHRASE
from app.models.answering import AnswerRequest, AnswerResponse

class KeywordLookupBaseline:
    """
    Baseline A: Pure text keyword search over document corpus.
    No knowledge graph, no multi-hop reasoning, no schema constraints.
    """
    def __init__(self, docs: Dict[str, Dict[str, Any]]):
        self.docs = docs

    def run(self, question: str) -> Dict[str, Any]:
        # Extract candidate terms from question
        words = [w.lower() for w in re.findall(r"\b[A-Za-z0-9_-]{3,}\b", question)]
        stopwords = {"what", "which", "does", "associated", "with", "from", "how", "attack", "systems", "and", "the"}
        query_terms = [w for w in words if w not in stopwords]

        matching_snippets = []
        matching_docs = set()
        for doc_id, doc in self.docs.items():
            text = doc["raw_text"]
            for term in query_terms:
                if term in text.lower():
                    matching_docs.add(doc_id)
                    # Extract 100-char window around match
                    idx = text.lower().find(term)
                    start = max(0, idx - 40)
                    end = min(len(text), idx + 80)
                    matching_snippets.append(text[start:end].strip())

        if not matching_docs or not matching_snippets:
            return {
                "question": question,
                "answer": ABSTENTION_PHRASE,
                "abstain": True,
                "retrieved_facts": [],
                "active_paths": [],
                "claims": [],
                "citations": []
            }

        direct_ans = f"Direct keyword matches found in documents: {', '.join(matching_docs)}. Snippets: {' [...] '.join(matching_snippets[:2])}"
        return {
            "question": question,
            "answer": direct_ans,
            "abstain": False,
            "retrieved_facts": [{"doc": d} for d in matching_docs],
            "active_paths": [],
            "claims": [{"claim_text": s, "verification_status": "unverified", "evidence_references": []} for s in matching_snippets[:2]],
            "citations": []
        }

class OneHopGraphBaseline:
    """
    Baseline B: 1-Hop Graph Retrieval without multi-hop reasoning or path templates.
    Resolves entities, retrieves direct neighbors only.
    """
    def __init__(self, repo=graph_repository, resolver=entity_resolver):
        self.repo = repo
        self.resolver = resolver

    def run(self, question: str) -> Dict[str, Any]:
        resolved_entities, unresolved = self.resolver.resolve(question)
        if not resolved_entities:
            return {
                "question": question,
                "answer": ABSTENTION_PHRASE,
                "abstain": True,
                "retrieved_facts": [],
                "active_paths": [],
                "claims": [],
                "citations": []
            }

        retrieved_edges = []
        for ent in resolved_entities:
            detail = self.repo.get_entity_with_neighbors(ent.id)
            if detail and detail.get("neighbors"):
                for n in detail["neighbors"]:
                    retrieved_edges.append({
                        "source": ent.name,
                        "rel_type": n.get("relationship", "ASSOCIATED_WITH"),
                        "target": n.get("name", "Unknown"),
                        "provenance": n.get("provenance", {})
                    })

        if not retrieved_edges:
            return {
                "question": question,
                "answer": ABSTENTION_PHRASE,
                "abstain": True,
                "retrieved_facts": [],
                "active_paths": [],
                "claims": [],
                "citations": []
            }

        ans_narrative = f"1-Hop graph lookup identified {len(retrieved_edges)} direct relationships connected to {resolved_entities[0].name}."
        paths = [[{"source": e["source"], "rel_type": e["rel_type"], "target": e["target"]}] for e in retrieved_edges]
        return {
            "question": question,
            "answer": ans_narrative,
            "abstain": False,
            "retrieved_facts": retrieved_edges,
            "active_paths": paths,
            "claims": [{"claim_text": f"{e['source']} {e['rel_type']} {e['target']}", "verification_status": "verified", "evidence_references": ["CIT-1"]} for e in retrieved_edges],
            "citations": [{"citation_id": "CIT-1", "evidence_id": "ev_1hop", "evidence_text": "Direct edge in knowledge graph"}]
        }

class ThreatMindPipelineEvaluator:
    """
    Evaluates the full ThreatMind pipeline (GraphRAG + Multi-Hop Reasoning + Grounded Answering).
    Operates in deterministic fallback mode or live LLM mode.
    """
    def __init__(self, generator: Optional[AnswerGenerator] = None):
        self.generator = generator or AnswerGenerator()

    def run(self, question: str) -> Dict[str, Any]:
        req = AnswerRequest(question=question, max_depth=3, max_paths=10)
        res: AnswerResponse = self.generator.generate_answer(req)
        direct_text = res.answer.direct_answer if res.answer else ""
        is_abstain = (
            res.grounding_status == "insufficient_evidence"
            or direct_text.strip() == ABSTENTION_PHRASE.strip()
            or len(res.graph_paths) == 0
        )

        facts = []
        for p in res.graph_paths:
            for s in p.steps:
                ev_text = s.evidence_records[0].evidence_text if s.evidence_records else ""
                facts.append({
                    "source": s.source_name,
                    "rel_type": s.rel_type,
                    "target": s.target_name,
                    "evidence_text": ev_text
                })

        return {
            "question": question,
            "answer": direct_text,
            "abstain": is_abstain,
            "grounding_status": res.grounding_status,
            "resolved_entities": res.resolved_entities,
            "unresolved_entities": res.unresolved_entities,
            "retrieved_facts": facts,
            "active_paths": [[{"source": s.source_name, "rel_type": s.rel_type, "target": s.target_name} for s in p.steps] for p in res.graph_paths],
            "claims": [c.model_dump() for c in res.claims],
            "citations": [c.model_dump() for c in res.citations],
            "execution_time_ms": res.statistics.get("execution_time_ms", 0.0)
        }
