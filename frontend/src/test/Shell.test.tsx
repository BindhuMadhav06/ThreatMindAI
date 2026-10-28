import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { Shell } from '../components/layout/Shell';
import { mockHealth } from './fixtures';

describe('Workstation Shell & Navigation', () => {
  it('renders application header with live health and provider details', () => {
    const handleTabChange = vi.fn();
    render(
      <Shell
        currentTab="dashboard"
        onTabChange={handleTabChange}
        health={mockHealth}
        loading={false}
        error={null}
      >
        <div>Content Area</div>
      </Shell>
    );

    expect(screen.getByText('ThreatMind AI')).toBeTruthy();
    expect(screen.getByText('ONLINE')).toBeTruthy();
    expect(screen.getByText('gemini (gemini-2.5-flash)')).toBeTruthy();
    expect(screen.getByText('Content Area')).toBeTruthy();
  });

  it('renders header offline state when health check fails', () => {
    render(
      <Shell
        currentTab="dashboard"
        onTabChange={vi.fn()}
        health={null}
        loading={false}
        error="Connection refused"
      >
        <div>Content Area</div>
      </Shell>
    );

    expect(screen.getByText('Disconnected')).toBeTruthy();
    expect(screen.getByText('UNAVAILABLE')).toBeTruthy();
  });

  it('triggers onTabChange when navigation links are clicked', () => {
    const handleTabChange = vi.fn();
    render(
      <Shell
        currentTab="dashboard"
        onTabChange={handleTabChange}
        health={mockHealth}
        loading={false}
        error={null}
      >
        <div>Content Area</div>
      </Shell>
    );

    const investigationBtn = screen.getByText('Threat Investigation');
    fireEvent.click(investigationBtn);

    expect(handleTabChange).toHaveBeenCalledWith('investigation');
  });
});
