import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { PathViewer } from '../components/investigation/PathViewer';
import { AccessibleGraphList } from '../components/graph/AccessibleGraphList';
import { GraphInspector, SelectedGraphItem } from '../components/graph/GraphInspector';
import { mockGroundedResponse } from './fixtures';

describe('Graph Paths, Inspector & Accessibility Components', () => {
  it('renders multi-hop reasoning path sequence and selection', () => {
    const handleSelectPath = vi.fn();
    render(
      <PathViewer
        paths={mockGroundedResponse.graph_paths}
        selectedPathId={null}
        onSelectPath={handleSelectPath}
      />
    );

    expect(screen.getByText('reason_path_0')).toBeTruthy();
    expect(screen.getByText('actor_tool_cve_product')).toBeTruthy();
    expect(screen.getByText(/APT29/)).toBeTruthy();
    expect(screen.getByText(/Cobalt Strike/)).toBeTruthy();
    expect(screen.getByText(/\[USES\]/)).toBeTruthy();

    const pathCard = screen.getByText('reason_path_0');
    fireEvent.click(pathCard);
    expect(handleSelectPath).toHaveBeenCalledWith('reason_path_0');
  });

  it('renders accessible textual list of graph relationships for screen readers', () => {
    render(<AccessibleGraphList paths={mockGroundedResponse.graph_paths} />);

    expect(screen.getByText('Textual Graph Structure (Accessibility View)')).toBeTruthy();
    expect(screen.getByText(/reason_path_0:/)).toBeTruthy();
  });

  it('renders graph inspector for selected node and edge', () => {
    const nodeItem: SelectedGraphItem = {
      type: 'node',
      id: 'actor_apt29',
      label: 'ThreatActor',
      name: 'APT29',
      properties: {
        description: 'Advanced persistent threat group.',
        aliases: ['Cozy Bear'],
      },
      is_synthetic: true,
    };

    const handleClose = vi.fn();
    const { rerender } = render(<GraphInspector item={nodeItem} onClose={handleClose} />);

    expect(screen.getByText('ThreatActor')).toBeTruthy();
    expect(screen.getByText('APT29')).toBeTruthy();
    expect(screen.getByText('actor_apt29')).toBeTruthy();
    expect(screen.getByText('Cozy Bear')).toBeTruthy();
    expect(screen.getByText('SYNTHETIC TEST FIXTURE ELEMENT')).toBeTruthy();

    // Rerender with edge item
    const edgeItem: SelectedGraphItem = {
      type: 'edge',
      id: 'actor_apt29-USES-malware_cobaltstrike',
      label: 'USES',
      source_name: 'APT29',
      target_name: 'Cobalt Strike',
      provenance: {
        evidence_text: 'APT29 deployed Cobalt Strike Beacon payloads.',
        source_id: 'source_demo_001',
      },
      is_synthetic: false,
    };

    rerender(<GraphInspector item={edgeItem} onClose={handleClose} />);
    expect(screen.getByText('RELATIONSHIP [USES]')).toBeTruthy();
    expect(screen.getByText(/"APT29 deployed Cobalt Strike Beacon payloads."/)).toBeTruthy();
  });
});
