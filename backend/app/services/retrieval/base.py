from abc import ABC, abstractmethod
from app.models.query import ThreatQuery, RetrievalResult

class BaseGraphRetriever(ABC):
    """
    Provider-independent interface for GraphRAG and Knowledge Graph retrieval in ThreatMind.
    Decouples retrieval logic from underlying graph query or vector engines.
    """

    @abstractmethod
    def retrieve(self, query: ThreatQuery) -> RetrievalResult:
        """
        Accepts a ThreatQuery and returns evidence-grounded graph context.
        Must NOT generate final natural-language answers.
        """
        pass
