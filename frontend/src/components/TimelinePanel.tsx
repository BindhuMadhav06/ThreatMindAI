import React, { useState, useEffect } from 'react';
import {
  Clock,
  AlertTriangle,
  GitCommit,
  Layers,
  RefreshCw,
  Plus,
  ShieldCheck,
  ChevronRight,
  ExternalLink,
} from 'lucide-react';

interface TimelineEventItem {
  id: string;
  title: string;
  description?: string;
  source_name: string;
  technique_id?: string;
  occurrence_start: string;
  occurrence_end?: string;
  confidence: number;
}

interface TimelineConflictItem {
  conflict_id: string;
  conflict_type: string;
  event_a_id: string;
  event_b_id: string;
  source_a: string;
  source_b: string;
  timestamp_a: string;
  timestamp_b: string;
  disparity_delta_seconds?: number;
  severity: string;
  explanation: string;
}

interface TimelineTrackItem {
  track_id: string;
  source_name: string;
  events: TimelineEventItem[];
}

export const TimelinePanel: React.FC = () => {
  const [tracks, setTracks] = useState<TimelineTrackItem[]>([]);
  const [conflicts, setConflicts] = useState<TimelineConflictItem[]>([]);
  const [hasDisputes, setHasDisputes] = useState(false);
  const [loading, setLoading] = useState(false);
  const [selectedSource, setSelectedSource] = useState<string>('all');

  const fetchTimeline = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/v1/timeline/events');
      if (res.ok) {
        const data = await res.json();
        setTracks(data.tracks || []);
        setConflicts(data.conflicts || []);
        setHasDisputes(data.has_disputes || false);
      }
    } catch (err) {
      console.error('Failed to load timeline:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTimeline();
  }, []);

  const filteredTracks = selectedSource === 'all'
    ? tracks
    : tracks.filter((t) => t.source_name === selectedSource);

  return (
    <div className="flex-1 flex flex-col h-full bg-slate-900 text-slate-100 overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b border-slate-800 bg-slate-950 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2 text-sky-400">
            <Clock className="w-6 h-6 text-sky-400" />
            Attack Timeline Reconstruction
          </h1>
          <p className="text-xs text-slate-400">
            Qualitative temporal ordering via Allen&apos;s Interval Algebra & multi-source parallel track preservation
          </p>
        </div>
        <button
          onClick={() => fetchTimeline()}
          className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded border border-slate-700 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
        </button>
      </div>

      {/* Disparity / Conflict Alert Banner */}
      {hasDisputes && (
        <div className="bg-amber-950/40 border-b border-amber-800/80 px-6 py-3 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="flex-1">
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-amber-300">
                Temporal Contradiction / Multi-Source Disparity Detected
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-amber-900/80 text-amber-300 font-mono">
                {conflicts.length} conflict(s)
              </span>
            </div>
            <p className="text-xs text-amber-200/80 mt-0.5">
              Conflicting timestamps from multiple intelligence sources are preserved on parallel tracks without lossy averaging.
            </p>
            <div className="mt-2 space-y-1.5">
              {conflicts.map((c) => (
                <div key={c.conflict_id} className="text-xs bg-amber-900/30 p-2 rounded border border-amber-800/50 text-amber-100">
                  <span className="font-semibold text-amber-300">[{c.conflict_type}]</span> {c.explanation}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Track Source Filter Tabs */}
      <div className="px-6 py-2.5 bg-slate-950/60 border-b border-slate-800 flex items-center gap-2 overflow-x-auto">
        <span className="text-xs text-slate-500 font-medium">Source Tracks:</span>
        <button
          onClick={() => setSelectedSource('all')}
          className={`px-2.5 py-1 text-xs rounded transition font-medium ${
            selectedSource === 'all'
              ? 'bg-sky-600 text-white'
              : 'bg-slate-800 text-slate-400 hover:text-slate-200'
          }`}
        >
          All Sources ({tracks.length})
        </button>
        {tracks.map((track) => (
          <button
            key={track.track_id}
            onClick={() => setSelectedSource(track.source_name)}
            className={`px-2.5 py-1 text-xs rounded transition font-medium flex items-center gap-1.5 ${
              selectedSource === track.source_name
                ? 'bg-sky-600 text-white'
                : 'bg-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            <span>{track.source_name}</span>
            <span className="text-[10px] bg-slate-900/80 px-1.5 py-0.2 rounded text-slate-300">
              {track.events.length}
            </span>
          </button>
        ))}
      </div>

      {/* Main Parallel Tracks View */}
      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {filteredTracks.map((track) => (
          <div key={track.track_id} className="bg-slate-950 border border-slate-800 rounded-lg p-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-4">
              <div className="flex items-center gap-2">
                <GitCommit className="w-4 h-4 text-sky-400" />
                <h3 className="text-sm font-bold text-slate-200">{track.source_name}</h3>
                <span className="text-xs text-slate-500 font-mono">({track.events.length} events)</span>
              </div>
              <span className="text-[10px] px-2 py-0.5 rounded bg-slate-900 text-slate-400 font-mono border border-slate-800">
                Track: {track.track_id}
              </span>
            </div>

            {/* Events Chronology */}
            <div className="relative pl-6 border-l-2 border-slate-800 space-y-4 ml-2">
              {track.events.map((ev) => {
                const isConflicted = conflicts.some(
                  (c) => c.event_a_id === ev.id || c.event_b_id === ev.id
                );
                return (
                  <div key={ev.id} className="relative group">
                    {/* Timeline Node Dot */}
                    <div
                      className={`absolute -left-[31px] top-1.5 w-3.5 h-3.5 rounded-full border-2 transition ${
                        isConflicted
                          ? 'bg-amber-500 border-amber-900'
                          : 'bg-sky-500 border-slate-950 group-hover:scale-125'
                      }`}
                    />

                    <div className="bg-slate-900/90 border border-slate-800 hover:border-slate-700 p-3 rounded-lg transition shadow-sm">
                      <div className="flex items-start justify-between">
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-bold text-slate-200">{ev.title}</span>
                            {ev.technique_id && (
                              <span className="text-[10px] px-1.5 py-0.2 rounded bg-sky-950 text-sky-300 border border-sky-800 font-mono">
                                {ev.technique_id}
                              </span>
                            )}
                            {isConflicted && (
                              <span className="text-[10px] px-1.5 py-0.2 rounded bg-amber-950 text-amber-300 border border-amber-800 flex items-center gap-1">
                                <AlertTriangle className="w-2.5 h-2.5" /> Disputed Time
                              </span>
                            )}
                          </div>
                          {ev.description && (
                            <p className="text-xs text-slate-400 mt-1 line-clamp-2">{ev.description}</p>
                          )}
                        </div>
                        <div className="text-right text-[11px] font-mono text-slate-400">
                          <div>{ev.occurrence_start.replace('T', ' ').replace('Z', ' UTC')}</div>
                          <div className="text-[10px] text-slate-500">Confidence: {(ev.confidence * 100).toFixed(0)}%</div>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
              {track.events.length === 0 && (
                <div className="text-xs text-slate-500 py-2">No timestamped events recorded on this track.</div>
              )}
            </div>
          </div>
        ))}

        {filteredTracks.length === 0 && !loading && (
          <div className="p-12 text-center text-slate-500 text-sm">
            No attack timeline tracks found. Ingest STIX reports or register timeline events to reconstruct tracks.
          </div>
        )}
      </div>
    </div>
  );
};
