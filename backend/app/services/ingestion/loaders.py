import fitz  # PyMuPDF
from bs4 import BeautifulSoup
import json
import hashlib
from typing import Optional, Dict, Any
from app.services.ingestion.models import ParsedDocument
from app.core.logging import logger

class DocumentLoader:
    """
    Multi-format CTI document acquisition and parsing service.
    Parses PDF, HTML, JSON, and TXT files safely without executing code.
    """

    @staticmethod
    def generate_source_id(content: str, filename: Optional[str] = None) -> str:
        """
        Generates a stable, reproducible source_id based on SHA-256 hash of content.
        """
        seed = (filename or "") + content[:1000]
        hash_digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]
        return f"source_{hash_digest}"

    @classmethod
    def load_pdf(cls, file_bytes: bytes, filename: str, metadata: Optional[Dict[str, Any]] = None) -> ParsedDocument:
        try:
            doc = fitz.open(stream=file_bytes, filetype="pdf")
            text_parts = []
            for page in doc:
                text_parts.append(page.get_text())
            full_text = "\n".join(text_parts).strip()
            
            source_id = cls.generate_source_id(full_text, filename)
            meta = metadata or {}
            title = meta.get("title") or filename
            
            return ParsedDocument(
                source_id=source_id,
                title=title,
                url=meta.get("url"),
                publisher=meta.get("publisher", "Unknown Publisher"),
                published_date=meta.get("published_date"),
                source_type="pdf",
                raw_text=full_text,
                metadata={"filename": filename, "pages": len(doc)},
                is_synthetic=meta.get("is_synthetic", False)
            )
        except Exception as e:
            logger.error(f"Error parsing PDF file '{filename}': {e}")
            raise ValueError(f"Failed to parse PDF file '{filename}': {e}")

    @classmethod
    def load_html(cls, html_content: str, filename: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> ParsedDocument:
        try:
            soup = BeautifulSoup(html_content, "html.parser")
            
            # Remove scripts, styles, and executable web tags
            for script in soup(["script", "style", "noscript", "iframe"]):
                script.extract()

            # Extract title if present
            extracted_title = soup.title.string.strip() if soup.title and soup.title.string else None
            text = soup.get_text(separator="\n").strip()
            
            # Remove excessive whitespace
            lines = [line.strip() for line in text.splitlines() if line.strip()]
            full_text = "\n".join(lines)
            
            meta = metadata or {}
            title = meta.get("title") or extracted_title or filename or "HTML CTI Document"
            source_id = cls.generate_source_id(full_text, filename or title)
            
            return ParsedDocument(
                source_id=source_id,
                title=title,
                url=meta.get("url"),
                publisher=meta.get("publisher", "Web CTI Source"),
                published_date=meta.get("published_date"),
                source_type="html",
                raw_text=full_text,
                metadata={"filename": filename},
                is_synthetic=meta.get("is_synthetic", False)
            )
        except Exception as e:
            logger.error(f"Error parsing HTML content: {e}")
            raise ValueError(f"Failed to parse HTML document: {e}")

    @classmethod
    def load_json(cls, json_content: str, filename: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> ParsedDocument:
        try:
            data = json.loads(json_content)
            meta = metadata or {}
            
            # Extract structured CTI text or serialize cleanly
            if isinstance(data, dict):
                title = data.get("title") or meta.get("title") or filename or "JSON CTI Advisory"
                url = data.get("url") or meta.get("url")
                publisher = data.get("publisher") or meta.get("publisher", "JSON CTI Provider")
                published_date = data.get("published_date") or meta.get("published_date")
                
                # If there is a 'content' or 'text' or 'description' field, use it
                text = data.get("content") or data.get("text") or data.get("description")
                if not text:
                    text = json.dumps(data, indent=2)
            else:
                title = filename or "JSON CTI Data"
                url = meta.get("url")
                publisher = meta.get("publisher", "JSON CTI Provider")
                published_date = meta.get("published_date")
                text = json.dumps(data, indent=2)

            source_id = meta.get("source_id") or cls.generate_source_id(text, filename or title)
            
            return ParsedDocument(
                source_id=source_id,
                title=title,
                url=url,
                publisher=publisher,
                published_date=published_date,
                source_type="json",
                raw_text=text,
                metadata={"filename": filename},
                is_synthetic=meta.get("is_synthetic", False)
            )
        except Exception as e:
            logger.error(f"Error parsing JSON content: {e}")
            raise ValueError(f"Failed to parse JSON document: {e}")

    @classmethod
    def load_txt(cls, text_content: str, filename: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> ParsedDocument:
        full_text = text_content.strip()
        meta = metadata or {}
        title = meta.get("title") or filename or "Plain Text CTI Advisory"
        source_id = meta.get("source_id") or cls.generate_source_id(full_text, filename or title)
        
        return ParsedDocument(
            source_id=source_id,
            title=title,
            url=meta.get("url"),
            publisher=meta.get("publisher", "Text CTI Advisory"),
            published_date=meta.get("published_date"),
            source_type="txt",
            raw_text=full_text,
            metadata={"filename": filename},
            is_synthetic=meta.get("is_synthetic", False)
        )
