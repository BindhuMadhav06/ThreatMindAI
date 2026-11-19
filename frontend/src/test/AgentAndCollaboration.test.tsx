import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import React from 'react';
import { InvestigationAgentPanel } from '../components/InvestigationAgentPanel';
import { CollaborativeSharingPanel } from '../components/CollaborativeSharingPanel';

describe('InvestigationAgentPanel (Phase 15)', () => {
  it('renders Investigation Agent header and Phase 15 badge', () => {
    render(<InvestigationAgentPanel />);
    expect(screen.getByText(/Trusted AI Investigation Agent/i)).toBeTruthy();
    expect(screen.getByText(/Phase 15/i)).toBeTruthy();
    expect(screen.getByText(/Read-Only Sandbox Enforced/i)).toBeTruthy();
  });

  it('displays grounded claims and analytical questions', () => {
    render(<InvestigationAgentPanel />);
    expect(screen.getByText(/Evidence-Grounded Agent Conclusions/i)).toBeTruthy();
    expect(screen.getByText(/APT29 executes PowerShell download cradles/i)).toBeTruthy();
    expect(screen.getByText(/What is Known\?/i)).toBeTruthy();
    expect(screen.getByText(/What is Unknown\?/i)).toBeTruthy();
    expect(screen.getByText(/What Contradicts Current Hypothesis\?/i)).toBeTruthy();
    expect(screen.getByText(/What Evidence is Stale\?/i)).toBeTruthy();
  });

  it('navigates to HITL action approval queue and reviews an action', () => {
    render(<InvestigationAgentPanel />);
    const hitlTab = screen.getByRole('button', { name: /HITL Action Approvals/i });
    fireEvent.click(hitlTab);

    expect(screen.getByText(/Human-in-the-Loop \(HITL\) Defensive Action Approval Queue/i)).toBeTruthy();
    expect(screen.getByText(/Deploy Sigma detection rule/i)).toBeTruthy();

    const approveButtons = screen.getAllByRole('button', { name: /Approve & Enforce/i });
    expect(approveButtons.length).toBeGreaterThan(0);
    fireEvent.click(approveButtons[0]);

    // Verify approval status updated
    expect(screen.getByText(/APPROVED/i)).toBeTruthy();
  });

  it('displays tool execution traces and blocked permission alerts', () => {
    render(<InvestigationAgentPanel />);
    const tracesTab = screen.getByRole('button', { name: /Tool Execution Traces/i });
    fireEvent.click(tracesTab);

    expect(screen.getByText(/Auditable Tool Execution Traces/i)).toBeTruthy();
    expect(screen.getByText(/READ_GRAPH_ENTITY/i)).toBeTruthy();
    expect(screen.getByText(/EXECUTE_SHELL_COMMAND/i)).toBeTruthy();
    expect(screen.getByText(/BLOCKED: Arbitrary shell execution forbidden/i)).toBeTruthy();
  });

  it('displays reproducible report digest envelope', () => {
    render(<InvestigationAgentPanel />);
    const reportTab = screen.getByRole('button', { name: /Structured Report & Reproducibility/i });
    fireEvent.click(reportTab);

    expect(screen.getByText(/Reproducible Investigation Report Envelope/i)).toBeTruthy();
    expect(screen.getByText(/Reproducibility Digest \(RFC 8785\):/i)).toBeTruthy();
    expect(screen.getByText(/6b7e9231f8a8461a9bc24df97b772ad389e18b76df42951e70e28198f12d8a55/i)).toBeTruthy();
  });
});

describe('CollaborativeSharingPanel (Phase 16)', () => {
  it('renders Collaborative Sharing header and Phase 16 badge', () => {
    render(<CollaborativeSharingPanel />);
    expect(screen.getByText(/Privacy-Preserving Collaborative Intelligence & TAXII 2.1/i)).toBeTruthy();
    expect(screen.getByText(/Phase 16/i)).toBeTruthy();
  });

  it('simulates salted HMAC pseudonymization on internal identifiers', () => {
    render(<CollaborativeSharingPanel />);
    expect(screen.getByText(/Tenant-Isolated Salted HMAC Anonymization Simulator/i)).toBeTruthy();

    const anonBtn = screen.getByRole('button', { name: /Anonymize/i });
    fireEvent.click(anonBtn);

    expect(screen.getByText(/Cryptographic Transformation Output:/i)).toBeTruthy();
    expect(screen.getByText(/pseudonym-ip-/i)).toBeTruthy();
  });

  it('evaluates TLP policy and enforces TLP:RED suppression', () => {
    render(<CollaborativeSharingPanel />);
    const policyTab = screen.getByRole('button', { name: /TLP & Sharing Policy Engine/i });
    fireEvent.click(policyTab);

    expect(screen.getByText(/Sharing Policy Evaluation & TLP Gating/i)).toBeTruthy();
    const evalBtn = screen.getByRole('button', { name: /Evaluate Policy Decision/i });
    fireEvent.click(evalBtn);

    expect(screen.getByText(/SHARING FORBIDDEN/i)).toBeTruthy();
    expect(screen.getByText(/TLP:RED intelligence strictly restricted/i)).toBeTruthy();
  });

  it('displays federated TAXII 2.1 collections and retraction ledger', () => {
    render(<CollaborativeSharingPanel />);
    const taxiiTab = screen.getByRole('button', { name: /TAXII 2.1 Federation Collections/i });
    fireEvent.click(taxiiTab);

    expect(screen.getByText(/TAXII 2.1 Federated Collections/i)).toBeTruthy();
    expect(screen.getByText(/Community ISAC Threat Feed/i)).toBeTruthy();
    expect(screen.getByText(/Public CTI Observable Exchange/i)).toBeTruthy();

    const retTab = screen.getByRole('button', { name: /Retraction & Superseding Ledger/i });
    fireEvent.click(retTab);

    expect(screen.getByText(/Collaborative Intelligence Retraction & Superseding/i)).toBeTruthy();
  });
});
