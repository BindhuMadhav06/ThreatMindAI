import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { AnswerCard } from '../components/investigation/AnswerCard';
import { mockGroundedResponse, mockAbstentionResponse } from './fixtures';

describe('AnswerCard Grounded Response Rendering', () => {
  it('renders grounded answer with inline citations and synthetic disclosure', () => {
    const handleSelectCitation = vi.fn();
    render(
      <AnswerCard
        answer={mockGroundedResponse.answer}
        groundingStatus={mockGroundedResponse.grounding_status}
        warnings={mockGroundedResponse.warnings}
        unresolvedEntities={mockGroundedResponse.unresolved_entities}
        onSelectCitation={handleSelectCitation}
      />
    );

    expect(screen.getByText('Evidence-Grounded Investigation Findings')).toBeTruthy();
    expect(screen.getByText('Fully Grounded')).toBeTruthy();
    expect(screen.getByText(/APT29 leverages Cobalt Strike Beacon/)).toBeTruthy();

    // Check inline citation buttons
    const cit1Btn = screen.getByText('[CIT-1]');
    expect(cit1Btn).toBeTruthy();
    fireEvent.click(cit1Btn);
    expect(handleSelectCitation).toHaveBeenCalledWith('CIT-1');

    // Check synthetic disclosure
    expect(screen.getByText(/Synthetic Demonstration Data Notice/)).toBeTruthy();
  });

  it('renders strict abstention response when evidence is insufficient', () => {
    const handleSelectCitation = vi.fn();
    render(
      <AnswerCard
        answer={mockAbstentionResponse.answer}
        groundingStatus={mockAbstentionResponse.grounding_status}
        warnings={mockAbstentionResponse.warnings}
        unresolvedEntities={mockAbstentionResponse.unresolved_entities}
        onSelectCitation={handleSelectCitation}
      />
    );

    expect(screen.getByText('Insufficient Evidence')).toBeTruthy();
    expect(
      screen.getByText('ThreatMind could not establish a sufficiently supported relationship from the currently available sources.')
    ).toBeTruthy();
    expect(screen.getByText('CompletelyUnknownGroup999')).toBeTruthy();
  });
});
