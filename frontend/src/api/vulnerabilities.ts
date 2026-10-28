import { apiClient } from './client';
import { VulnerabilityIntelResponse } from '../types/api';

export async function getVulnerabilityIntel(
  cveId: string,
  forceLive: boolean = false,
  signal?: AbortSignal
): Promise<VulnerabilityIntelResponse> {
  const response = await apiClient.get<VulnerabilityIntelResponse>(
    `/vulnerabilities/${encodeURIComponent(cveId)}/intel`,
    {
      params: forceLive ? { force_live: true } : undefined,
      signal,
    }
  );
  return response.data;
}
