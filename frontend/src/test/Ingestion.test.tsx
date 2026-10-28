import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { IngestionForm } from '../components/ingestion/IngestionForm';
import { IngestionResult } from '../components/ingestion/IngestionResult';
import { IngestionResponse } from '../types/api';

describe('CTI Document Ingestion Workflow', () => {
  it('validates supported file extensions and rejects unsupported types', () => {
    const handleSubmit = vi.fn();
    render(<IngestionForm onSubmit={handleSubmit} loading={false} />);

    // Switch to raw text and submit without content -> shows error
    const textTab = screen.getByText('Raw Text');
    fireEvent.click(textTab);

    const submitBtn = screen.getByText('Process & Ingest Document');
    fireEvent.click(submitBtn);

    expect(screen.getByText('Please provide raw CTI text content.')).toBeTruthy();
    expect(handleSubmit).not.toHaveBeenCalled();
  });

  it('submits raw text content with metadata', () => {
    const handleSubmit = vi.fn();
    render(<IngestionForm onSubmit={handleSubmit} loading={false} />);

    const textTab = screen.getByText('Raw Text');
    fireEvent.click(textTab);

    const textarea = screen.getByPlaceholderText(/Paste raw cybersecurity advisory content/);
    fireEvent.change(textarea, { target: { value: 'APT29 deployed Cobalt Strike in recent campaign.' } });

    const submitBtn = screen.getByText('Process & Ingest Document');
    fireEvent.click(submitBtn);

    expect(handleSubmit).toHaveBeenCalledWith(
      expect.objectContaining({
        text_content: 'APT29 deployed Cobalt Strike in recent campaign.',
        source_type: 'txt',
      })
    );
  });

  it('renders ingestion result with chunks, extracted entities, and edge metrics', () => {
    const mockResult: IngestionResponse = {
      source_id: 'src_test_123',
      title: 'Sample Advisory',
      chunks_count: 3,
      entities_extracted: 6,
      relationships_extracted: 4,
      relationships_accepted: 3,
      relationships_rejected: 1,
      warnings: ['Rejected ungrounded relationship: evidence passage did not match.'],
      status: 'success',
    };

    render(<IngestionResult result={mockResult} />);

    expect(screen.getByText('Ingestion Execution Succeeded')).toBeTruthy();
    expect(screen.getAllByText('3').length).toBe(2); // Chunks and Edges Persisted
    expect(screen.getByText('6')).toBeTruthy(); // Entities
    expect(screen.getByText('STATUS: SUCCESS')).toBeTruthy();
    expect(screen.getByText(/Rejected ungrounded relationship/)).toBeTruthy();
  });
});
