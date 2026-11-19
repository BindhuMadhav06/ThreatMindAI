import React, { useState, useEffect } from 'react';
import { Shell } from './components/layout/Shell';
import { NavTab } from './components/layout/Sidebar';
import { Dashboard } from './pages/Dashboard';
import { InvestigationPage } from './pages/InvestigationPage';
import { KnowledgeGraphPage } from './pages/KnowledgeGraphPage';
import { IngestionPage } from './pages/IngestionPage';
import { EntitiesPage } from './pages/EntitiesPage';
import { DetectionPanel } from './components/DetectionPanel';
import { TimelinePanel } from './components/TimelinePanel';
import { SystemHealth } from './types/api';
import { fetchHealth } from './api/health';
import { parseApiError } from './api/client';

export default function App() {
  const [currentTab, setCurrentTab] = useState<NavTab>('dashboard');
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [healthLoading, setHealthLoading] = useState(true);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [selectedQuery, setSelectedQuery] = useState<string | null>(null);

  const checkHealth = () => {
    fetchHealth()
      .then((data) => {
        setHealth(data);
        setHealthError(null);
        setHealthLoading(false);
      })
      .catch((err) => {
        setHealthError(parseApiError(err));
        setHealthLoading(false);
      });
  };

  useEffect(() => {
    checkHealth();
    // Poll health every 30 seconds
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <Shell
      currentTab={currentTab}
      onTabChange={setCurrentTab}
      health={health}
      loading={healthLoading}
      error={healthError}
    >
      {currentTab === 'dashboard' && (
        <Dashboard
          health={health}
          healthLoading={healthLoading}
          healthError={healthError}
          onNavigate={setCurrentTab}
          onSelectRecentQuery={(q) => {
            setSelectedQuery(q);
            setCurrentTab('investigation');
          }}
        />
      )}

      {currentTab === 'investigation' && (
        <InvestigationPage initialQuery={selectedQuery} />
      )}

      {currentTab === 'graph' && <KnowledgeGraphPage />}

      {currentTab === 'ingestion' && <IngestionPage />}

      {currentTab === 'entities' && <EntitiesPage />}

      {currentTab === 'detection' && <DetectionPanel />}

      {currentTab === 'timeline' && <TimelinePanel />}
    </Shell>
  );
}
