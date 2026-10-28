from fastapi import APIRouter, UploadFile, File, Form, HTTPException, status
from typing import Optional
from app.services.ingestion.loaders import DocumentLoader
from app.services.ingestion.pipeline import IngestionPipeline
from app.services.ingestion.models import IngestionResponse, ParsedDocument
from app.core.logging import logger

router = APIRouter()

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB limit

@router.post("/ingestion", response_model=IngestionResponse, summary="Ingest CTI document into Knowledge Graph")
async def ingest_document(
    file: Optional[UploadFile] = File(None),
    text_content: Optional[str] = Form(None),
    title: Optional[str] = Form(None),
    url: Optional[str] = Form(None),
    publisher: Optional[str] = Form(None),
    published_date: Optional[str] = Form(None),
    source_type: Optional[str] = Form("txt")
):
    """
    Ingests a CTI document (PDF, HTML, JSON, or TXT), extracts entities and relationships,
    validates strict evidence groundings, and persists graph nodes & edges into Neo4j.
    """
    metadata = {
        "title": title,
        "url": url,
        "publisher": publisher,
        "published_date": published_date
    }

    try:
        parsed_doc: Optional[ParsedDocument] = None

        if file:
            content_bytes = await file.read()
            if len(content_bytes) > MAX_FILE_SIZE:
                raise HTTPException(status_code=400, detail="File size exceeds 10MB limit.")

            filename = file.filename or "uploaded_cti_doc"
            ext = filename.split(".")[-1].lower() if "." in filename else ""

            if ext == "pdf":
                parsed_doc = DocumentLoader.load_pdf(content_bytes, filename, metadata)
            elif ext in ["html", "htm"]:
                parsed_doc = DocumentLoader.load_html(content_bytes.decode("utf-8", errors="ignore"), filename, metadata)
            elif ext == "json":
                parsed_doc = DocumentLoader.load_json(content_bytes.decode("utf-8", errors="ignore"), filename, metadata)
            else:
                parsed_doc = DocumentLoader.load_txt(content_bytes.decode("utf-8", errors="ignore"), filename, metadata)

        elif text_content:
            if source_type == "json":
                parsed_doc = DocumentLoader.load_json(text_content, title, metadata)
            elif source_type == "html":
                parsed_doc = DocumentLoader.load_html(text_content, title, metadata)
            else:
                parsed_doc = DocumentLoader.load_txt(text_content, title, metadata)

        else:
            raise HTTPException(status_code=400, detail="Either a file upload or text_content must be provided.")

        pipeline = IngestionPipeline()
        response = pipeline.process_document(parsed_doc)
        return response

    except HTTPException:
        raise
    except ValueError as ve:
        logger.error(f"Ingestion validation error: {ve}")
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.error(f"Ingestion server error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to process ingestion document: {str(e)}")
