import React from 'react';
import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { DefensesPanel } from '../components/defense/DefensesPanel';
import { mockDefensiveResponse, mockEmptyDefensiveResponse } from './fixtures';

describe('DefensesPanel Component', () => {
  it('renders loading state correctly', () => {
    render(<DefensesPanel defenseData={null} loading={true} />);

    expect(screen.getByRole('status')).toBeTruthy();
    expect(
      screen.getByText('Mapping attack techniques to MITRE D3FEND™ countermeasures...')
    ).toBeTruthy();
  });

  it('renders error state correctly', () => {
    render(
      <DefensesPanel
        defenseData={null}
        loading={false}
        error="D3FEND service connection timed out"
      />
    );

    const alert = screen.getByRole('alert');
    expect(alert).toBeTruthy();
    expect(screen.getByText('Defensive Recommendations Error')).toBeTruthy();
    expect(screen.getByText('D3FEND service connection timed out')).toBeTruthy();
  });

  it('renders empty state when no recommendations match', () => {
    render(<DefensesPanel defenseData={mockEmptyDefensiveResponse} loading={false} />);

    expect(
      screen.getByText('No MITRE D3FEND™ defensive countermeasures mapped for the identified techniques.')
    ).toBeTruthy();
  });

  it('renders nothing when defenseData is null and not loading', () => {
    const { container } = render(<DefensesPanel defenseData={null} loading={false} />);
    expect(container.firstChild).toBeNull();
  });

  it('renders populated recommendations with offensive, mitigation, and applicability badges', () => {
    render(<DefensesPanel defenseData={mockDefensiveResponse} loading={false} />);

    // Header & summary
    expect(screen.getByText('Recommended Defenses (MITRE D3FEND™)')).toBeTruthy();
    expect(screen.getByText('2 Countermeasures')).toBeTruthy();
    expect(screen.getByText('Harden: 2')).toBeTruthy();

    // Recommendation 1: T1059.001 -> M1042 -> D3-ACH
    expect(screen.getByText('Offensive: T1059.001 (PowerShell)')).toBeTruthy();
    expect(
      screen.getByText('Mitigation: M1042 (Disable or Remove Feature or Program)')
    ).toBeTruthy();
    expect(screen.getByText('Application Configuration Hardening')).toBeTruthy();
    expect(screen.getByText('[D3-ACH]')).toBeTruthy();
    expect(screen.getByText('Officially mapped')).toBeTruthy();

    // Recommendation 2: T1055 -> app:inferred_memory_protection
    expect(screen.getByText(/Offensive: T1055/)).toBeTruthy();
    expect(screen.getByText('Inferred Memory Protection')).toBeTruthy();
    expect(screen.getByText('[app:inferred_memory_protection]')).toBeTruthy();
    expect(screen.getByText('Potentially relevant')).toBeTruthy();

    // Catalog provenance footer
    expect(screen.getByText(/Catalog: 0.9.0-BETA/)).toBeTruthy();
    expect(screen.getByText(/Snapshot: 2024-04-15/)).toBeTruthy();
  });

  it('expands details drawer and suppresses canonical hyperlink for app-inferred countermeasures', () => {
    render(<DefensesPanel defenseData={mockDefensiveResponse} loading={false} />);

    // Expand official countermeasure (D3-ACH)
    const achTitle = screen.getByText('Application Configuration Hardening');
    fireEvent.click(achTitle);

    expect(
      screen.getByText('Configuring software systems to enforce secure execution policies.')
    ).toBeTruthy();
    expect(
      screen.getByText('Requires PowerShell v5+ and AppLocker / WDAC enforcement telemetry.')
    ).toBeTruthy();
    expect(screen.getByText('Provenance: mitre_official_mapping')).toBeTruthy();

    // Canonical link exists for official countermeasure
    const mitreLink = screen.getByRole('link', { name: /Canonical MITRE Reference/i });
    expect(mitreLink).toBeTruthy();
    expect(mitreLink.getAttribute('href')).toBe(
      'https://d3fend.mitre.org/technique/d3f:ApplicationConfigurationHardening'
    );

    // Expand app-inferred countermeasure (app:inferred_memory_protection)
    const inferredTitle = screen.getByText('Inferred Memory Protection');
    fireEvent.click(inferredTitle);

    expect(
      screen.getByText('Application-defined conceptual defense representing dynamic memory exploit protections.')
    ).toBeTruthy();
    expect(screen.getByText('Provenance: application_defined_inference')).toBeTruthy();

    // Disallowed canonical link check: MUST show notice instead of link
    expect(
      screen.getByText('Application-defined conceptual defense (not an official D3FEND technique)')
    ).toBeTruthy();

    // Ensure there is only 1 canonical MITRE link in the document (for D3-ACH only)
    const links = screen.getAllByRole('link', { name: /Canonical MITRE Reference/i });
    expect(links.length).toBe(1);
  });
});
