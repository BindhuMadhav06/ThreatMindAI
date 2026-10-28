import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { InvestigationPage } from '../pages/InvestigationPage';
import { GraphInspector, SelectedGraphItem } from '../components/graph/GraphInspector';
import { DefensesPanel } from '../components/defense/DefensesPanel';
import { VulnerabilityCard } from '../components/vulnerability/VulnerabilityCard';
import {
  mockGroundedResponse,
  mockDefensiveResponse,
  mockVulnerabilityIntelFresh,
  mockVulnerabilityIntelStaleKev,
} from './fixtures';
import * as investApi from '../api/investigations';
import * as defApi from '../api/defense';
import * as vulnApi from '../api/vulnerabilities';

vi.mock('../api/investigations', () => ({
  askQuestion: vi.fn(),
}));

vi.mock('../api/defense', () => ({
  getDefensesBatch: vi.fn(),
}));

vi.mock('../api/vulnerabilities', () => ({
  getVulnerabilityIntel: vi.fn(),
}));

// Mock Cytoscape canvas renderer for jsdom environment
vi.mock('../components/graph/CytoscapeGraph', () => ({
  CytoscapeGraph: () => <div data-testid="cytoscape-mock" />,
}));

describe('Phase 11D — Release Verification End-to-End Suite', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // --------------------------------------------------------------------------
  // Check 1: Complete User Journey (Investigation Page with Defenses & CVEs)
  // --------------------------------------------------------------------------
  it('Journey 1: Investigation workflow automatically surfaces D3FEND defenses and CVE intel alongside grounded answer and citations', async () => {
    const customResponse = {
      ...mockGroundedResponse,
      original_question: 'Analyze Log4Shell CVE-2021-44228 exploitation invoking PowerShell T1059.001',
      answer: {
        ...mockGroundedResponse.answer,
        summary: 'Log4Shell CVE-2021-44228 allows attackers to invoke PowerShell T1059.001 stagers.',
        direct_answer: 'Exploitation of CVE-2021-44228 enables execution of PowerShell T1059.001 commands [CIT-1].',
      },
    };

    vi.mocked(investApi.askQuestion).mockResolvedValue(customResponse);
    vi.mocked(defApi.getDefensesBatch).mockResolvedValue(mockDefensiveResponse);
    vi.mocked(vulnApi.getVulnerabilityIntel).mockResolvedValue(mockVulnerabilityIntelFresh);

    render(<InvestigationPage />);

    // Enter question and submit
    const input = screen.getByPlaceholderText(/Ask an evidence-grounded threat question/i);
    fireEvent.change(input, { target: { value: 'Analyze Log4Shell CVE-2021-44228 and PowerShell' } });
    const submitBtn = screen.getByRole('button', { name: /Investigate Query/i });
    fireEvent.click(submitBtn);

    // Verify investigation answer is rendered
    await waitFor(() => {
      expect(screen.getByText('Evidence-Grounded Investigation Findings')).toBeTruthy();
    });

    // Verify CVE auto-detection and VulnerabilityCard rendering
    expect(screen.getByText(/Sourced Vulnerability Intelligence \(1 Referenced\)/i)).toBeTruthy();
    expect(screen.getByText(/Grounding: Narrative \/ Query Reference/i)).toBeTruthy();
    expect(screen.getByText('CVE-2021-44228')).toBeTruthy();
    expect(screen.getByText('LIVE API')).toBeTruthy();
    expect(screen.getByText('Critical')).toBeTruthy();
    expect(screen.getByText('CISA KEV LISTED')).toBeTruthy();

    // Verify MITRE D3FEND Defensive Panel rendering with grounding awareness
    expect(screen.getByText('Recommended Defenses (MITRE D3FEND™)')).toBeTruthy();
    expect(screen.getByText('Offensive: T1059.001 (PowerShell)')).toBeTruthy();
    expect(screen.getByText('Graph Verified')).toBeTruthy(); // T1059.001 is in mockGroundedResponse.graph_paths!
    expect(screen.getByText('Application Configuration Hardening')).toBeTruthy();

    // Verify citation interaction preserves original citation drawer capability
    const cit1Btns = screen.getAllByText('[CIT-1]');
    expect(cit1Btns.length).toBeGreaterThanOrEqual(1);
    fireEvent.click(cit1Btns[0]);
    expect(screen.getByText('Evidence Provenance Record')).toBeTruthy();
    expect(screen.getByText('Verbatim Evidence Passage')).toBeTruthy();
  });

  // --------------------------------------------------------------------------
  // Check 2: Graph Inspector Integration Journey
  // --------------------------------------------------------------------------
  it('Journey 2: GraphInspector embeds VulnerabilityCard when node is a Vulnerability with CVE ID', async () => {
    vi.mocked(vulnApi.getVulnerabilityIntel).mockResolvedValue(mockVulnerabilityIntelFresh);

    const vulnNode: SelectedGraphItem = {
      type: 'node',
      id: 'vuln_cve_2021_44228',
      label: 'Vulnerability',
      name: 'CVE-2021-44228',
      properties: {
        description: 'Apache Log4j2 JNDI remote code execution vulnerability.',
      },
    };

    const handleClose = vi.fn();
    render(<GraphInspector item={vulnNode} onClose={handleClose} />);

    expect(screen.getByText('Vulnerability')).toBeTruthy();
    expect(screen.getByText('vuln_cve_2021_44228')).toBeTruthy();

    // Vulnerability card is automatically embedded and resolves async
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Refresh Live/i })).toBeTruthy();
    });
    // Check that CVE identifier appears in both inspector header and card
    const cveElements = screen.getAllByText('CVE-2021-44228');
    expect(cveElements.length).toBeGreaterThanOrEqual(2);
  });

  // --------------------------------------------------------------------------
  // Check 3: Defensive Mapping Integrity & App Inference Guardrail
  // --------------------------------------------------------------------------
  it('Mapping Integrity: Official countermeasures render canonical links, app: inferences suppress links and show disclaimer', () => {
    render(<DefensesPanel defenseData={mockDefensiveResponse} />);

    // Expand official countermeasure
    fireEvent.click(screen.getByText('Application Configuration Hardening'));
    const canonicalLink = screen.getByRole('link', { name: /Canonical MITRE Reference/i });
    expect(canonicalLink.getAttribute('href')).toContain('d3fend.mitre.org');
    expect(canonicalLink.getAttribute('rel')).toBe('noopener noreferrer');
    expect(canonicalLink.getAttribute('target')).toBe('_blank');

    // Expand app-inferred countermeasure
    fireEvent.click(screen.getByText('Inferred Memory Protection'));
    expect(
      screen.getByText('Application-defined conceptual defense (not an official D3FEND technique)')
    ).toBeTruthy();

    // Ensure no link was created for app:inferred_memory_protection
    const allLinks = screen.getAllByRole('link', { name: /Canonical MITRE Reference/i });
    expect(allLinks.length).toBe(1); // Only for D3-ACH
  });

  // --------------------------------------------------------------------------
  // Check 4: Source Attribution, Freshness & Stale KEV Guardrail
  // --------------------------------------------------------------------------
  it('Freshness & KEV Safety: Stale snapshot triggers explicit warning and never claims live absence', () => {
    render(
      <VulnerabilityCard
        cveId="CVE-2019-14287"
        initialIntel={mockVulnerabilityIntelStaleKev}
      />
    );

    // Badges indicate offline fixture and stale
    expect(screen.getByText('OFFLINE FIXTURE')).toBeTruthy();
    expect(screen.getByText('HISTORICAL / STALE')).toBeTruthy();

    // Verify KEV status is 'Not in CISA KEV' from snapshot
    expect(screen.getByText('Not in CISA KEV')).toBeTruthy();

    // Prominent Stale Snapshot Notice guardrail MUST be present
    const notice = screen.getByRole('alert', { name: /Historical snapshot warning/i });
    expect(notice).toBeTruthy();
    expect(
      screen.getByText(/A stale snapshot does not establish current absence from the live CISA KEV catalog\./i)
    ).toBeTruthy();
  });

  // --------------------------------------------------------------------------
  // Check 5: Security & Accessibility Compliance
  // --------------------------------------------------------------------------
  it('Security & Accessibility: Safely escapes external HTML strings and declares accessible roles', () => {
    const maliciousIntel = {
      ...mockVulnerabilityIntelFresh,
      title: '<script>alert("xss")</script> Malicious Vulnerability',
      description: '<img src=x onerror=alert(1)> Untrusted vector string',
      cvss: {
        ...mockVulnerabilityIntelFresh.cvss,
        vector_string: '<svg onload=alert(2)> CVSS:3.1/AV:N',
      },
    };

    render(
      <VulnerabilityCard
        cveId="CVE-2021-44228"
        initialIntel={maliciousIntel}
      />
    );

    // Verify strings are rendered safely as text content, not executable HTML
    expect(
      screen.getByText('<script>alert("xss")</script> Malicious Vulnerability')
    ).toBeTruthy();
    expect(
      screen.getByText('<img src=x onerror=alert(1)> Untrusted vector string')
    ).toBeTruthy();

    // Verify all interactive buttons have accessible type="button"
    const buttons = screen.getAllByRole('button');
    buttons.forEach((btn) => {
      expect(btn.getAttribute('type')).toBe('button');
    });

    // Verify external links have target="_blank" and rel="noopener noreferrer"
    const links = screen.getAllByRole('link');
    links.forEach((l) => {
      expect(l.getAttribute('target')).toBe('_blank');
      expect(l.getAttribute('rel')).toBe('noopener noreferrer');
    });
  });

  // --------------------------------------------------------------------------
  // Check 6: Error Resilience & Graceful Degraded States
  // --------------------------------------------------------------------------
  it('Resilience: DefensesPanel and VulnerabilityCard handle API failures cleanly without crashing view', async () => {
    // Defenses panel error state
    render(<DefensesPanel defenseData={null} error="Failed to connect to MITRE D3FEND service" />);
    expect(screen.getByRole('alert')).toBeTruthy();
    expect(screen.getByText('Failed to connect to MITRE D3FEND service')).toBeTruthy();

    // Vulnerability card error state handled gracefully
    vi.mocked(vulnApi.getVulnerabilityIntel).mockRejectedValue(new Error('Network lookup failure'));
    render(<VulnerabilityCard cveId="CVE-2099-99999" />);

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeTruthy();
    });
    expect(screen.getByText(/Unable to load vulnerability intelligence/i)).toBeTruthy();
  });

  // --------------------------------------------------------------------------
  // Check 7: Provenance Separation (Graph Verified vs Narrative Only)
  // --------------------------------------------------------------------------
  it('Evidence Provenance: Differentiates verified graph entity from narrative-only concept mention', async () => {
    // Response where CVE-2021-44228 is in graph_paths, and CVE-2019-14287 is only in query text
    const dualResponse = {
      ...mockGroundedResponse,
      original_question: 'Compare CVE-2019-14287 narrative mention with confirmed Log4j CVE-2021-44228',
      graph_paths: [
        {
          ...mockGroundedResponse.graph_paths[0],
          steps: [
            ...mockGroundedResponse.graph_paths[0].steps,
            {
              step_number: 3,
              source_id: 'tech_t1059_001',
              source_name: 'PowerShell',
              source_label: 'Technique',
              rel_type: 'EXPLOITS',
              target_id: 'vuln_cve_2021_44228',
              target_name: 'CVE-2021-44228',
              target_label: 'Vulnerability',
              is_valid: true,
              evidence_records: [],
            },
          ],
        },
      ],
    };

    vi.mocked(investApi.askQuestion).mockResolvedValue(dualResponse);
    vi.mocked(defApi.getDefensesBatch).mockResolvedValue(mockDefensiveResponse);
    vi.mocked(vulnApi.getVulnerabilityIntel).mockResolvedValue(mockVulnerabilityIntelFresh);

    render(<InvestigationPage />);

    const input = screen.getByPlaceholderText(/Ask an evidence-grounded threat question/i);
    fireEvent.change(input, { target: { value: 'Compare CVE-2019-14287 with CVE-2021-44228' } });
    fireEvent.click(screen.getByRole('button', { name: /Investigate Query/i }));

    await waitFor(() => {
      expect(screen.getByText('Evidence-Grounded Investigation Findings')).toBeTruthy();
    });

    // CVE-2021-44228 is in graph_paths -> Must show "Verified Knowledge Graph Entity"
    expect(screen.getByText(/Grounding: Verified Knowledge Graph Entity/i)).toBeTruthy();

    // CVE-2019-14287 is only in query text -> Must show "Narrative / Query Reference"
    expect(screen.getByText(/Grounding: Narrative \/ Query Reference/i)).toBeTruthy();
  });
});
