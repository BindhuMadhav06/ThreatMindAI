import React, { useEffect, useRef, useState, useMemo } from 'react';
import cytoscape, { Core, EventObject } from 'cytoscape';
import { EvidenceBackedPath } from '../../types/api';
import { GraphInspector, SelectedGraphItem } from './GraphInspector';
import { AccessibleGraphList } from './AccessibleGraphList';
import { ZoomIn, ZoomOut, Maximize2, RotateCcw, ListFilter } from 'lucide-react';

interface CytoscapeGraphProps {
  paths?: EvidenceBackedPath[];
  customElements?: any[];
  selectedPathId?: string | null;
  height?: string;
  className?: string;
}

const LABEL_COLORS: Record<string, string> = {
  ThreatActor: '#f43f5e',
  Malware: '#f97316',
  Tool: '#f59e0b',
  Vulnerability: '#8b5cf6',
  Technique: '#3b82f6',
  Tactic: '#60a5fa',
  Product: '#10b981',
  Software: '#059669',
  OperatingSystem: '#06b6d4',
  Organization: '#14b8a6',
  Indicator: '#ec4899',
  Source: '#94a3b8',
};

export const CytoscapeGraph: React.FC<CytoscapeGraphProps> = ({
  paths = [],
  customElements,
  selectedPathId,
  height = '500px',
  className = '',
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [selectedItem, setSelectedItem] = useState<SelectedGraphItem | null>(null);
  const [showAccessibleList, setShowAccessibleList] = useState(false);

  // Convert paths into Cytoscape elements (nodes & edges)
  const elements = useMemo(() => {
    if (customElements && customElements.length > 0) {
      return customElements;
    }

    const nodesMap = new Map<string, any>();
    const edgesMap = new Map<string, any>();

    paths.forEach((path) => {
      path.steps.forEach((step) => {
        // Source node
        if (!nodesMap.has(step.source_id)) {
          nodesMap.set(step.source_id, {
            data: {
              id: step.source_id,
              name: step.source_name,
              label: step.source_label,
              color: LABEL_COLORS[step.source_label] || '#64748b',
              paths: [path.path_id],
            },
          });
        } else {
          nodesMap.get(step.source_id).data.paths.push(path.path_id);
        }

        // Target node
        if (!nodesMap.has(step.target_id)) {
          nodesMap.set(step.target_id, {
            data: {
              id: step.target_id,
              name: step.target_name,
              label: step.target_label,
              color: LABEL_COLORS[step.target_label] || '#64748b',
              paths: [path.path_id],
            },
          });
        } else {
          nodesMap.get(step.target_id).data.paths.push(path.path_id);
        }

        // Edge
        const edgeId = `${step.source_id}-${step.rel_type}-${step.target_id}`;
        const firstEvidence = step.evidence_records?.[0];
        if (!edgesMap.has(edgeId)) {
          edgesMap.set(edgeId, {
            data: {
              id: edgeId,
              source: step.source_id,
              target: step.target_id,
              label: step.rel_type,
              source_name: step.source_name,
              target_name: step.target_name,
              path_id: path.path_id,
              provenance: firstEvidence
                ? {
                    evidence_text: firstEvidence.evidence_text,
                    source_id: firstEvidence.source_id,
                    source_url: firstEvidence.source_url,
                  }
                : {},
              paths: [path.path_id],
            },
          });
        } else {
          edgesMap.get(edgeId).data.paths.push(path.path_id);
        }
      });
    });

    return [...Array.from(nodesMap.values()), ...Array.from(edgesMap.values())];
  }, [paths, customElements]);

  useEffect(() => {
    if (!containerRef.current) return;

    // Initialize Cytoscape
    const cy = cytoscape({
      container: containerRef.current,
      elements: elements,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': 'data(color)',
            label: 'data(name)',
            'font-size': '11px',
            'font-weight': 600,
            color: '#e2e8f0',
            'text-valign': 'bottom',
            'text-margin-y': 4,
            'text-background-color': '#020617',
            'text-background-opacity': 0.8,
            'text-background-padding': '2px',
            'text-background-shape': 'roundrectangle',
            width: 32,
            height: 32,
            'border-width': 2,
            'border-color': '#1e293b',
          },
        },
        {
          selector: 'edge',
          style: {
            width: 2,
            'line-color': '#475569',
            'target-arrow-color': '#475569',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            label: 'data(label)',
            'font-size': '9px',
            'font-family': 'monospace',
            color: '#94a3b8',
            'text-background-color': '#0f172a',
            'text-background-opacity': 0.85,
            'text-background-padding': '1px',
            'text-rotation': 'autorotate',
          },
        },
        {
          selector: '.highlighted',
          style: {
            'line-color': '#06b6d4',
            'target-arrow-color': '#06b6d4',
            width: 3.5,
            'border-color': '#22d3ee',
            'border-width': 3,
            opacity: 1,
            'z-index': 10,
          },
        },
        {
          selector: '.dimmed',
          style: {
            opacity: 0.25,
          },
        },
      ],
      layout: {
        name: 'breadthfirst',
        directed: true,
        padding: 40,
        spacingFactor: 1.25,
      },
    });

    cyRef.current = cy;
    if (typeof window !== 'undefined') {
      (window as any).__CYTOSCAPE_INSTANCE__ = cy;
      (window as any).__CYTOSCAPE_SELECT_ITEM__ = setSelectedItem;
    }

    // Node click / select
    cy.on('tap select', 'node', (evt: EventObject) => {
      const node = evt.target;
      setSelectedItem({
        type: 'node',
        id: node.id(),
        label: node.data('label') || 'Entity',
        name: node.data('name'),
        properties: node.data('properties') || {},
        is_synthetic: node.data('is_synthetic'),
      });
    });

    // Edge click / select
    cy.on('tap select', 'edge', (evt: EventObject) => {
      const edge = evt.target;
      setSelectedItem({
        type: 'edge',
        id: edge.id(),
        label: edge.data('label') || 'RELATIONSHIP',
        source_name: edge.data('source_name'),
        target_name: edge.data('target_name'),
        provenance: edge.data('provenance') || {},
        is_synthetic: edge.data('is_synthetic'),
      });
    });

    // Background click
    cy.on('tap', (evt: EventObject) => {
      if (evt.target === cy) {
        setSelectedItem(null);
      }
    });

    return () => {
      cy.destroy();
      cyRef.current = null;
      if (typeof window !== 'undefined' && (window as any).__CYTOSCAPE_INSTANCE__ === cy) {
        (window as any).__CYTOSCAPE_INSTANCE__ = null;
      }
    };
  }, [elements]);

  // Handle path highlighting
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    if (!selectedPathId) {
      cy.elements().removeClass('highlighted dimmed');
      return;
    }

    cy.batch(() => {
      cy.elements().addClass('dimmed').removeClass('highlighted');

      // Highlight nodes & edges matching selectedPathId
      cy.elements().forEach((el) => {
        const pathList: string[] = el.data('paths') || [];
        if (pathList.includes(selectedPathId)) {
          el.removeClass('dimmed').addClass('highlighted');
        }
      });
    });
  }, [selectedPathId]);

  const handleZoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.25);
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() * 0.8);
  const handleFit = () => cyRef.current?.fit(undefined, 30);
  const handleResetLayout = () => {
    cyRef.current?.layout({ name: 'breadthfirst', directed: true, padding: 40 }).run();
  };

  return (
    <div className={`relative bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-xl ${className}`}>
      {/* Legend & Controls Toolbar */}
      <div className="absolute top-3 left-3 z-10 flex flex-wrap items-center gap-2 bg-slate-900/90 backdrop-blur-md p-1.5 rounded-lg border border-slate-800 text-[11px]">
        <div className="flex items-center gap-1.5 px-2 border-r border-slate-800">
          <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
          <span className="text-slate-400">Actor</span>
          <span className="w-2.5 h-2.5 rounded-full bg-orange-500 ml-1" />
          <span className="text-slate-400">Malware</span>
          <span className="w-2.5 h-2.5 rounded-full bg-purple-500 ml-1" />
          <span className="text-slate-400">CVE</span>
          <span className="w-2.5 h-2.5 rounded-full bg-blue-500 ml-1" />
          <span className="text-slate-400">Technique</span>
        </div>

        <button
          onClick={handleZoomIn}
          className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800"
          title="Zoom In"
        >
          <ZoomIn className="w-4 h-4" />
        </button>
        <button
          onClick={handleZoomOut}
          className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800"
          title="Zoom Out"
        >
          <ZoomOut className="w-4 h-4" />
        </button>
        <button
          onClick={handleFit}
          className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800"
          title="Fit Graph to Canvas"
        >
          <Maximize2 className="w-4 h-4" />
        </button>
        <button
          onClick={handleResetLayout}
          className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800"
          title="Reset Layout"
        >
          <RotateCcw className="w-4 h-4" />
        </button>
        <button
          onClick={() => setShowAccessibleList(!showAccessibleList)}
          className={`p-1 rounded ${showAccessibleList ? 'bg-cyan-950 text-cyan-300' : 'text-slate-400 hover:bg-slate-800'}`}
          title="Toggle Textual Relationship List"
        >
          <ListFilter className="w-4 h-4" />
        </button>
      </div>

      {/* Graph Canvas */}
      <div
        ref={containerRef}
        data-testid="cytoscape-container"
        style={{ height }}
        className="w-full bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:16px_16px]"
      />

      {/* Node / Edge Inspector Modal */}
      <GraphInspector item={selectedItem} onClose={() => setSelectedItem(null)} />

      {/* Empty State */}
      {elements.length === 0 && (
        <div className="absolute inset-0 flex items-center justify-center text-slate-500 text-xs">
          No graph nodes or relationships to display. Run an investigation to visualize threat paths.
        </div>
      )}

      {/* Accessible Textual List */}
      {showAccessibleList && (
        <div className="p-4 border-t border-slate-800">
          <AccessibleGraphList paths={paths} />
        </div>
      )}
    </div>
  );
};
