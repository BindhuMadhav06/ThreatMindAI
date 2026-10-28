from app.core.config import settings
from app.core.logging import logger
from app.services.llm.base_provider import BaseLLMProvider
from app.services.llm.gemini_provider import GeminiProvider

def get_llm_provider() -> BaseLLMProvider:
    provider = settings.LLM_PROVIDER.lower()
    
    if provider == "gemini":
        return GeminiProvider()
    else:
        logger.warning(f"Unsupported LLM provider '{provider}'. Falling back to GeminiProvider.")
        return GeminiProvider()
