import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import React from 'react';
import { DetectionPanel } from '../components/DetectionPanel';
import { TimelinePanel } from '../components/TimelinePanel';

describe('DetectionPanel Component', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation((url: string) => {
        if (url.includes('/api/v1/detection/rules')) {
          return Promise.resolve({
            ok: true,
            json: () =>
              Promise.resolve([
                {
                  id: 'sigma-rule-01',
                  title: 'Suspicious PowerShell Download Cradle',
                  level: 'high',
                  status: 'experimental',
                  tags: ['attack.execution', 'attack.t1059.001'],
                  raw_yaml: 'title: Suspicious PowerShell\nlevel: high',
                  threatmind_provenance: {
                    rule_id: 'sigma-rule-01',
                    technique_id: 'T1059.001',
                    technique_name: 'PowerShell',
                    tactics: ['execution'],
                    d3fend_countermeasures: ['D3-PA: Process Analysis'],
                    evidence_text_snippets: ['powershell.exe -enc ...'],
                    confidence_score: 0.95,
                    review_status: 'draft',
                    review_notes: [],
                  },
                },
              ]),
          });
        }
        return Promise.reject(new Error('Unknown URL'));
      })
    );
  });

  it('renders DetectionPanel with title and rule list', async () => {
    render(<DetectionPanel />);
    expect(screen.getByText(/SigmaHQ Detection Engineering/i)).toBeTruthy();
    expect(screen.getByText(/Generate Rule/i)).toBeTruthy();

    await waitFor(() => {
      const items = screen.getAllByText(/Suspicious PowerShell Download Cradle/i);
      expect(items.length).toBeGreaterThan(0);
    });
  });
});

describe('TimelinePanel Component', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation((url: string) => {
        if (url.includes('/api/v1/timeline/events')) {
          return Promise.resolve({
            ok: true,
            json: () =>
              Promise.resolve({
                tracks: [
                  {
                    track_id: 'track-crowdstrike',
                    source_name: 'CrowdStrike Intelligence',
                    events: [
                      {
                        id: 'ev-01',
                        title: 'Initial Access',
                        source_name: 'CrowdStrike Intelligence',
                        technique_id: 'T1566',
                        occurrence_start: '2026-02-15T02:00:00Z',
                        confidence: 0.9,
                      },
                    ],
                  },
                ],
                total_events: 1,
                conflicts: [
                  {
                    conflict_id: 'c-01',
                    conflict_type: 'TIMESTAMP_DISPARITY',
                    event_a_id: 'ev-01',
                    event_b_id: 'ev-02',
                    source_a: 'CrowdStrike Intelligence',
                    source_b: 'CISA Advisory',
                    timestamp_a: '2026-02-15T02:00:00Z',
                    timestamp_b: '2026-02-15T08:00:00Z',
                    disparity_delta_seconds: 21600,
                    severity: 'high',
                    explanation: 'Discrepancy: 6.0 hours between CrowdStrike and CISA.',
                  },
                ],
                has_disputes: true,
              }),
          });
        }
        return Promise.reject(new Error('Unknown URL'));
      })
    );
  });

  it('renders TimelinePanel with dispute alert and source tracks', async () => {
    render(<TimelinePanel />);
    expect(screen.getByText(/Attack Timeline Reconstruction/i)).toBeTruthy();

    await waitFor(() => {
      expect(screen.getByText(/Temporal Contradiction \/ Multi-Source Disparity Detected/i)).toBeTruthy();
      const sources = screen.getAllByText(/CrowdStrike Intelligence/i);
      expect(sources.length).toBeGreaterThan(0);
    });
  });
});
