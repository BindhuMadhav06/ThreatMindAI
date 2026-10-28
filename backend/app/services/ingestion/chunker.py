import re
from typing import List
from app.services.ingestion.models import ParsedDocument, TextChunk

class TextChunker:
    """
    Semantic text cleaner and paragraph chunker for CTI documents.
    """

    @staticmethod
    def clean_text(text: str) -> str:
        """
        Removes control characters, weird unicode spaces, and unneeded whitespace.
        """
        if not text:
            return ""
        cleaned = re.sub(r'[\r\t\f\v]', ' ', text)
        lines = [re.sub(r' +', ' ', line).strip() for line in cleaned.splitlines()]
        text_joined = "\n".join(lines)
        return re.sub(r'\n{3,}', '\n\n', text_joined).strip()

    @classmethod
    def chunk_document(cls, doc: ParsedDocument, target_words_per_chunk: int = 250) -> List[TextChunk]:
        """
        Splits a parsed document into semantic text chunks while respecting paragraph boundaries.
        """
        cleaned_text = cls.clean_text(doc.raw_text)
        if not cleaned_text:
            return []

        paragraphs = [p.strip() for p in cleaned_text.split("\n\n") if p.strip()]
        chunks = []
        current_words = []
        chunk_idx = 0

        for para in paragraphs:
            para_words = para.split()
            if len(current_words) + len(para_words) > target_words_per_chunk and current_words:
                chunk_text = " ".join(current_words)
                chunks.append(TextChunk(
                    chunk_id=f"{doc.source_id}_chunk_{chunk_idx}",
                    source_id=doc.source_id,
                    chunk_index=chunk_idx,
                    text=chunk_text,
                    word_count=len(current_words)
                ))
                chunk_idx += 1
                current_words = []

            current_words.extend(para_words)

        if current_words:
            chunk_text = " ".join(current_words)
            chunks.append(TextChunk(
                chunk_id=f"{doc.source_id}_chunk_{chunk_idx}",
                source_id=doc.source_id,
                chunk_index=chunk_idx,
                text=chunk_text,
                word_count=len(current_words)
            ))

        return chunks
