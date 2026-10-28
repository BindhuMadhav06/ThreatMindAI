import { apiClient } from './client';
import { GraphStats, EntitySummary, EntityDetail } from '../types/api';

export async function fetchGraphStats(signal?: AbortSignal): Promise<GraphStats> {
  const response = await apiClient.get<GraphStats>('/graph/stats', { signal });
  return response.data;
}

export async function fetchEntities(
  params?: { label?: string; search?: string; limit?: number },
  signal?: AbortSignal
): Promise<EntitySummary[]> {
  const response = await apiClient.get<EntitySummary[]>('/entities', {
    params,
    signal,
  });
  return response.data;
}

export async function fetchEntityDetails(
  entityId: string,
  signal?: AbortSignal
): Promise<EntityDetail> {
  const response = await apiClient.get<EntityDetail>(`/entities/${encodeURIComponent(entityId)}`, {
    signal,
  });
  return response.data;
}
