import pytest
import sys
import os
import fitz

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.services.ingestion.loaders import DocumentLoader

def test_load_txt():
    text = "APT29 deployed Cobalt Strike in recent targeted operations against European government sectors."
    doc = DocumentLoader.load_txt(text, filename="apt29_advisory.txt", metadata={"title": "APT29 Advisory"})
    assert doc.source_id.startswith("source_")
    assert doc.title == "APT29 Advisory"
    assert doc.source_type == "txt"
    assert "Cobalt Strike" in doc.raw_text

def test_load_html():
    html_content = """
    <html>
        <head><title>CISA Advisory Log4Shell</title></head>
        <body>
            <script>alert('xss');</script>
            <h1>Vulnerability Notice</h1>
            <p>CVE-2021-44228 affects Apache Log4j library versions 2.0 through 2.14.1.</p>
        </body>
    </html>
    """
    doc = DocumentLoader.load_html(html_content, filename="log4j.html")
    assert doc.title == "CISA Advisory Log4Shell"
    assert "alert" not in doc.raw_text  # Script tag stripped
    assert "CVE-2021-44228" in doc.raw_text

def test_load_json():
    json_data = '{"title": "Synthetic Threat Report", "publisher": "Mandiant", "text": "Lazarus Group utilizes Mimikatz for credential harvesting."}'
    doc = DocumentLoader.load_json(json_data, filename="lazarus.json")
    assert doc.title == "Synthetic Threat Report"
    assert doc.publisher == "Mandiant"
    assert "Mimikatz" in doc.raw_text

def test_load_pdf():
    pdf_doc = fitz.open()
    page = pdf_doc.new_page()
    page.insert_text((50, 72), "ThreatActor APT28 conducts phishing campaigns exploiting CVE-2023-38831.")
    pdf_bytes = pdf_doc.tobytes()
    pdf_doc.close()

    parsed = DocumentLoader.load_pdf(pdf_bytes, filename="threat_report.pdf", metadata={"title": "PDF Threat Report"})
    assert parsed.source_type == "pdf"
    assert parsed.title == "PDF Threat Report"
    assert "APT28" in parsed.raw_text
    assert "CVE-2023-38831" in parsed.raw_text
