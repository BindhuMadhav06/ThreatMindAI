import { apiClient } from './client';
import { SystemHealth } from '../types/api';

export async function fetchHealth(signal?: AbortSignal): Promise<SystemHealth> {
  const response = await apiClient.get<SystemHealth>('/health', { signal });
  return response.data;
}
