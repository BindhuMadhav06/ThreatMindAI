from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class BaseLLMProvider(ABC):
    """
    Provider-independent abstraction interface for LLMs in ThreatMind.
    Decouples domain reasoning from specific LLM APIs.
    """

    @abstractmethod
    def generate_response(
        self,
        prompt: str,
        system_instruction: Optional[str] = None,
        temperature: float = 0.2
    ) -> str:
        """
        Generate text response for a given prompt and system instructions.
        """
        pass

    @abstractmethod
    def generate_structured_output(
        self,
        prompt: str,
        schema: Any,
        system_instruction: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate Pydantic-validated structured JSON output.
        """
        pass

    @abstractmethod
    def get_provider_name(self) -> str:
        """
        Return provider identifier (e.g., 'gemini', 'openai', 'ollama').
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if API key and configuration for this provider are valid.
        """
        pass
