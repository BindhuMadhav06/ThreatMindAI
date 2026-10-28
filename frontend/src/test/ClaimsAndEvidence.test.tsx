import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { ClaimsList } from '../components/investigation/ClaimsList';
import { CitationDrawer } from '../components/evidence/CitationDrawer';
import { mockGroundedResponse } from './fixtures';
import { AnswerCitation, AnswerClaim } from '../types/api';

describe('Claims & Evidence Provenance Inspection', () => {
  it('renders claim list with verification statuses and validation reasons', () => {
    const claims: AnswerClaim[] = [
      {
        claim_text: 'APT29 deployed Cobalt Strike Beacon payloads.',
        evidence_references: ['CIT-1'],
        claim_type: 'relationship',
        verification_status: 'verified',
        validation_reasons: ['Claim verified against cited passage.'],
      },
      {
        claim_text: 'APT29 successfully breached the power grid.',
        evidence_references: ['CIT-1'],
        claim_type: 'relationship',
        verification_status: 'unverified',
        validation_reasons: ['Claim asserts unproven attack success not documented in cited text.'],
      },
    ];

    const handleSelectCit = vi.fn();
    render(<ClaimsList claims={claims} onSelectCitation={handleSelectCit} />);

    expect(screen.getByText('VERIFIED')).toBeTruthy();
    expect(screen.getByText('UNVERIFIED')).toBeTruthy();
    expect(screen.getByText('APT29 successfully breached the power grid.')).toBeTruthy();
    expect(screen.getByText(/asserts unproven attack success/)).toBeTruthy();
  });

  it('renders citation drawer with verbatim quote and provenance metadata', () => {
    const cit = mockGroundedResponse.citations[0];
    const handleClose = vi.fn();

    render(<CitationDrawer citation={cit} isOpen={true} onClose={handleClose} />);

    expect(screen.getByText('[CIT-1]')).toBeTruthy();
    expect(screen.getByText('ev_a1b2c3d4e5f6')).toBeTruthy();
    expect(screen.getByText(/"\[Synthetic Evidence\] APT29 has deployed Cobalt Strike Beacon payloads/)).toBeTruthy();
    expect(screen.getByText('(APT29)-[USES]->(Cobalt Strike)')).toBeTruthy();
    expect(screen.getByText('Synthetic CTI Report: APT29 Campaign Analysis')).toBeTruthy();
    expect(screen.getByText('ThreatMind Demo Research Labs')).toBeTruthy();
    expect(screen.getByText('2026-01-15')).toBeTruthy();
    expect(screen.getByText('https://threatmind.demo/advisories/APT29-2026-SYNTHETIC')).toBeTruthy();

    const closeBtn = screen.getByLabelText('Close drawer');
    fireEvent.click(closeBtn);
    expect(handleClose).toHaveBeenCalled();
  });

  it('renders unavailable for missing optional metadata without guessing', () => {
    const sparseCit: AnswerCitation = {
      citation_id: 'CIT-3',
      evidence_id: 'ev_1234567890ab',
      source_id: 'src_sparse',
      source_title: null,
      source_url: null,
      publisher: null,
      published_date: null,
      evidence_text: 'Observed technique usage without additional metadata.',
      supported_relationship: '(A)-[USES]->(B)',
      confidence: null,
      is_synthetic: false,
    };

    render(<CitationDrawer citation={sparseCit} isOpen={true} onClose={vi.fn()} />);

    expect(screen.getAllByText('Unavailable').length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText('No external URL provided')).toBeTruthy();
    expect(screen.getByText('Unknown (Not quantitatively calculated)')).toBeTruthy();
  });
});
