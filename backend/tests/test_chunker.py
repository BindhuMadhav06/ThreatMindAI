import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.services.ingestion.loaders import DocumentLoader
from app.services.ingestion.chunker import TextChunker

def test_clean_text():
    raw = "   APT29 \t\t deployed   \n\n\n\n Cobalt   Strike.  "
    cleaned = TextChunker.clean_text(raw)
    assert cleaned == "APT29 deployed\n\nCobalt Strike."

def test_chunk_document():
    para1 = "Paragraph one describes APT29 using Cobalt Strike Beacon for persistence. " * 10
    para2 = "Paragraph two details PowerShell execution (T1059.001) for lateral movement. " * 10
    full_text = f"{para1}\n\n{para2}"
    
    doc = DocumentLoader.load_txt(full_text, filename="test_chunks.txt")
    chunks = TextChunker.chunk_document(doc, target_words_per_chunk=50)
    
    assert len(chunks) >= 2
    assert chunks[0].source_id == doc.source_id
    assert chunks[0].chunk_index == 0
    assert "Cobalt Strike" in chunks[0].text
