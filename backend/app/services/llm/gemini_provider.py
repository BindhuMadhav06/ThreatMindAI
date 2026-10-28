import json
from typing import Dict, Any, Optional
from app.services.llm.base_provider import BaseLLMProvider
from app.core.config import settings
from app.core.logging import logger

class GeminiProvider(BaseLLMProvider):
    def __init__(self):
        self.model_name = settings.GEMINI_MODEL
        self.api_key = settings.GEMINI_API_KEY
        self._client = None
        self._initialize_client()

    def _initialize_client(self):
        if not self.api_key or self.api_key == "mock_key_for_dev":
            logger.warning("Gemini API key is not configured or using mock key. Real LLM calls will use fallback responses.")
            return

        try:
            from google import genai
            self._client = genai.Client(api_key=self.api_key)
            logger.info(f"Successfully initialized Google Gemini client with model '{self.model_name}'.")
        except Exception as e:
            logger.error(f"Failed to initialize Google Gemini client: {str(e)}")
            self._client = None

    def get_provider_name(self) -> str:
        return f"gemini ({self.model_name})"

    def is_available(self) -> bool:
        return self._client is not None and bool(self.api_key) and self.api_key != "mock_key_for_dev"

    def generate_response(
        self,
        prompt: str,
        system_instruction: Optional[str] = None,
        temperature: float = 0.2
    ) -> str:
        if not self.is_available():
            logger.warning("Gemini API client unavailable. Returning grounded fallback response.")
            return f"[Dev Fallback Response]: Generated answer based on retrieved evidence for prompt: {prompt[:100]}..."

        try:
            config = {}
            if system_instruction:
                config["system_instruction"] = system_instruction
            config["temperature"] = temperature

            response = self._client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=config
            )
            return response.text
        except Exception as e:
            logger.error(f"Error calling Gemini API generate_content: {str(e)}")
            return f"[LLM Error]: Unable to complete response generation: {str(e)}"

    def generate_structured_output(
        self,
        prompt: str,
        schema: Any,
        system_instruction: Optional[str] = None
    ) -> Dict[str, Any]:
        if not self.is_available():
            logger.warning("Gemini API client unavailable. Returning empty structured schema.")
            return {}

        try:
            config = {
                "response_mime_type": "application/json",
                "response_schema": schema
            }
            if system_instruction:
                config["system_instruction"] = system_instruction

            response = self._client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=config
            )
            return json.loads(response.text)
        except Exception as e:
            logger.error(f"Error generating structured Gemini output: {str(e)}")
            return {}
