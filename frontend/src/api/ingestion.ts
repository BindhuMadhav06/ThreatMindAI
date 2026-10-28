import { apiClient } from './client';
import { IngestionResponse } from '../types/api';

export interface IngestDocumentParams {
  file?: File;
  text_content?: string;
  title?: string;
  url?: string;
  publisher?: string;
  published_date?: string;
  source_type?: string;
}

export async function ingestDocument(
  params: IngestDocumentParams
): Promise<IngestionResponse> {
  const formData = new FormData();

  if (params.file) {
    formData.append('file', params.file);
  }
  if (params.text_content) {
    formData.append('text_content', params.text_content);
  }
  if (params.title) {
    formData.append('title', params.title);
  }
  if (params.url) {
    formData.append('url', params.url);
  }
  if (params.publisher) {
    formData.append('publisher', params.publisher);
  }
  if (params.published_date) {
    formData.append('published_date', params.published_date);
  }
  if (params.source_type) {
    formData.append('source_type', params.source_type);
  }

  // NOTE: Ingestion does NOT automatically retry on network error to prevent repeated ingestion
  const response = await apiClient.post<IngestionResponse>('/ingestion', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });

  return response.data;
}
