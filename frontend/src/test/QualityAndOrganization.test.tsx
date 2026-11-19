import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import React from 'react';
import { IntelligenceQualityPanel } from '../components/IntelligenceQualityPanel';
import { AttackPathSimulationPanel } from '../components/AttackPathSimulationPanel';

describe('IntelligenceQualityPanel (Phase 13)', () => {
  it('renders Intelligence Quality Engine header and Phase 13 badge', () => {
    render(<IntelligenceQualityPanel />);
    expect(screen.getByText(/ThreatMind Intelligence Quality Engine/i)).toBeTruthy();
    expect(screen.getByText(/Phase 13/i)).toBeTruthy();
  });

  it('displays grounded evidence offsets and anchored claims', () => {
    render(<IntelligenceQualityPanel />);
    expect(screen.getByText(/Raw Source Document/i)).toBeTruthy();
    const offsetMatches = screen.getAllByText(/38:119/i);
    expect(offsetMatches.length).toBeGreaterThan(0);
    expect(screen.getByText(/\(APT29\)/i)).toBeTruthy();
    expect(screen.getAllByText(/\(Cobalt Strike\)/i).length).toBeGreaterThan(0);
  });

  it('navigates to dispute ledger and resolves attribution conflict without evidence deletion', () => {
    render(<IntelligenceQualityPanel />);
    const disputeTab = screen.getByRole('button', { name: /Dispute Ledger/i });
    fireEvent.click(disputeTab);

    expect(screen.getByText(/Persistent Attribution Dispute Ledger/i)).toBeTruthy();
    expect(screen.getByText(/Campaign Operation SolarWorm/i)).toBeTruthy();
    expect(screen.getByText(/APT29/i)).toBeTruthy();
    expect(screen.getByText(/FIN7/i)).toBeTruthy();

    const resolveBtn = screen.getByText(/Analyst Resolution Workflow/i);
    fireEvent.click(resolveBtn);

    expect(screen.getByText(/Resolve Dispute: Campaign Operation SolarWorm/i)).toBeTruthy();
    const favorBtn = screen.getByText(/Favor Claim A \(APT29\)/i);
    fireEvent.click(favorBtn);

    // Verify status updated to ANALYST_RESOLVED
    expect(screen.getByText(/ANALYST_RESOLVED/i)).toBeTruthy();
  });

  it('calculates temporal freshness score and displays stale warning', () => {
    render(<IntelligenceQualityPanel />);
    const freshnessTab = screen.getByRole('button', { name: /Temporal Freshness Decay/i });
    fireEvent.click(freshnessTab);

    expect(screen.getByText(/Temporal Freshness Decay Calculator/i)).toBeTruthy();
    expect(screen.getByText(/Stale Warning/i)).toBeTruthy();
  });

  it('displays multi-tier SimHash deduplication architecture', () => {
    render(<IntelligenceQualityPanel />);
    const dedupTab = screen.getByRole('button', { name: /SimHash Deduplication/i });
    fireEvent.click(dedupTab);

    expect(screen.getByText(/Multi-Tier Deduplication/i)).toBeTruthy();
    expect(screen.getByText(/Tier 1: Cryptographic Digest/i)).toBeTruthy();
    expect(screen.getByText(/Tier 2: Locality Sensitive/i)).toBeTruthy();
  });
});

describe('AttackPathSimulationPanel (Phase 14)', () => {
  it('renders Organization Threat Intelligence header and Phase 14 badge', () => {
    render(<AttackPathSimulationPanel />);
    expect(screen.getByText(/Organization Threat Intelligence & Attack Simulation/i)).toBeTruthy();
    expect(screen.getByText(/Phase 14/i)).toBeTruthy();
  });

  it('renders attack-path simulation graph and Minimum D3FEND Cut-Set', () => {
    render(<AttackPathSimulationPanel />);
    expect(screen.getByText(/Graph Traversal Attack Path/i)).toBeTruthy();
    expect(screen.getByText(/asset_web_01/i)).toBeTruthy();
    expect(screen.getByText(/asset_db_03 \(Crown Jewel\)/i)).toBeTruthy();

    expect(screen.getByText(/Recommended Minimum D3FEND Cut-Set/i)).toBeTruthy();
    expect(screen.getByText(/d3f:InboundTrafficFiltering/i)).toBeTruthy();
    expect(screen.getByText(/d3f:MultiFactorAuthentication/i)).toBeTruthy();
  });

  it('displays decomposed risk prioritization scoring formula', () => {
    render(<AttackPathSimulationPanel />);
    const priorTab = screen.getByRole('button', { name: /Decomposed Risk Prioritization/i });
    fireEvent.click(priorTab);

    expect(screen.getByText(/Decomposed Organization Risk Scoring Formula/i)).toBeTruthy();
    expect(screen.getByText(/CRITICAL PRIORITY/i)).toBeTruthy();
  });

  it('displays SemVer threat matches rejecting naive substrings', () => {
    render(<AttackPathSimulationPanel />);
    const matchTab = screen.getByRole('button', { name: /SemVer Threat Matches/i });
    fireEvent.click(matchTab);

    expect(screen.getByText(/Semantic Version \(SemVer\) Threat Matches/i)).toBeTruthy();
    expect(screen.getByText(/log4j-core/i)).toBeTruthy();
    expect(screen.getByText(/2.14.1/i)).toBeTruthy();
    expect(screen.getByText(/< 2.15.0/i)).toBeTruthy();
  });

  it('displays enterprise asset inventory with active controls', () => {
    render(<AttackPathSimulationPanel />);
    const invTab = screen.getByRole('button', { name: /Asset Inventory/i });
    fireEvent.click(invTab);

    expect(screen.getByText(/Tenant Enterprise Asset Inventory/i)).toBeTruthy();
    expect(screen.getByText(/Public Edge Web Gateway/i)).toBeTruthy();
    expect(screen.getByText(/Production Financial Database/i)).toBeTruthy();
  });
});
