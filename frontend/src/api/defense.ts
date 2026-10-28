import { apiClient } from './client';
import { DefensiveResponse, DefensiveRecommendation } from '../types/api';

export async function getDefensesForTechnique(
  techniqueId: string,
  signal?: AbortSignal
): Promise<DefensiveRecommendation[]> {
  const response = await apiClient.get<DefensiveRecommendation[]>(
    `/defense/techniques/${encodeURIComponent(techniqueId)}`,
    { signal }
  );
  return response.data;
}

export async function getDefensesBatch(
  techniqueIds: string[],
  signal?: AbortSignal
): Promise<DefensiveResponse> {
  const response = await apiClient.post<DefensiveResponse>(
    '/defense/recommend',
    { technique_ids: techniqueIds },
    { signal }
  );
  return response.data;
}
