import { apiClient } from './client';
import { AnswerRequest, AnswerResponse } from '../types/api';

export async function askQuestion(
  request: AnswerRequest,
  signal?: AbortSignal
): Promise<AnswerResponse> {
  const response = await apiClient.post<AnswerResponse>('/query/answer', request, { signal });
  return response.data;
}

export async function executeReasoning(
  request: AnswerRequest,
  signal?: AbortSignal
): Promise<any> {
  const response = await apiClient.post('/query/reason', request, { signal });
  return response.data;
}

export async function retrieveContext(
  request: { question: string; entity_hints?: string[] },
  signal?: AbortSignal
): Promise<any> {
  const response = await apiClient.post('/query/retrieve', request, { signal });
  return response.data;
}
