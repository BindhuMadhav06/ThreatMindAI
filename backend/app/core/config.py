import os
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # System
    PROJECT_NAME: str = "ThreatMind AI"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # Authentication & Cryptographic Security
    JWT_SECRET_KEY: str = "threatmind-dev-secret-key-change-in-production-min32bytes"
    JWT_ALGORITHM: str = "HS256"
    JWT_ISSUER: str = "threatmind-auth"
    JWT_AUDIENCE: str = "threatmind-api"
    JWT_EXPIRATION_MINUTES: int = 60

    # LLM Abstraction Settings
    LLM_PROVIDER: str = "gemini"
    GEMINI_MODEL: str = "gemini-2.5-flash"
    GEMINI_API_KEY: Optional[str] = None
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3"

    # Neo4j Database Settings
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USERNAME: str = "neo4j"
    NEO4J_PASSWORD: str = "password"
    NEO4J_DATABASE: str = "neo4j"

    # Embeddings
    EMBEDDING_MODEL: str = "all-MiniLM-L6-v2"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
