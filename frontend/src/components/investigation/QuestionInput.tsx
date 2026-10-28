import React, { useState } from 'react';
import { Search, XCircle, SlidersHorizontal, Sparkles } from 'lucide-react';

interface QuestionInputProps {
  onSubmit: (question: string, options?: { maxDepth?: number; maxPaths?: number; hints?: string[] }) => void;
  onCancel?: () => void;
  loading: boolean;
}

export const QuestionInput: React.FC<QuestionInputProps> = ({
  onSubmit,
  onCancel,
  loading,
}) => {
  const [question, setQuestion] = useState('');
  const [showOptions, setShowOptions] = useState(false);
  const [maxDepth, setMaxDepth] = useState(3);
  const [maxPaths, setMaxPaths] = useState(10);
  const [hintsText, setHintsText] = useState('');

  const exampleQuestions = [
    { label: 'APT29 Execution Chain', q: 'How does APT29 attack systems?' },
    { label: 'Vulnerability Impact', q: 'What vulnerabilities are exploited by APT29?' },
    { label: 'Unknown Actor (Abstention)', q: 'What techniques are used by CompletelyUnknownGroup999?' },
  ];

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!question.trim() || loading) return;

    const hints = hintsText
      .split(',')
      .map((h) => h.trim())
      .filter((h) => h.length > 0);

    onSubmit(question.trim(), {
      maxDepth,
      maxPaths,
      hints: hints.length > 0 ? hints : undefined,
    });
  };

  const handleSelectExample = (exQ: string) => {
    setQuestion(exQ);
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="question-input" className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
            Cyber Threat Investigation Query
          </label>
          <div className="relative">
            <textarea
              id="question-input"
              rows={3}
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              placeholder="Ask an evidence-grounded threat question (e.g. 'How does APT29 attack systems?')..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors resize-none"
              disabled={loading}
            />
          </div>
        </div>

        {/* Example Queries */}
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="text-[11px] text-slate-500 font-medium flex items-center gap-1">
            <Sparkles className="w-3 h-3 text-cyan-400" />
            Examples:
          </span>
          {exampleQuestions.map((ex, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => handleSelectExample(ex.q)}
              disabled={loading}
              className="px-2.5 py-1 rounded-md text-[11px] bg-slate-950 border border-slate-800 text-slate-400 hover:text-cyan-300 hover:border-cyan-800/80 transition-colors disabled:opacity-50"
            >
              {ex.label}
            </button>
          ))}
        </div>

        {/* Action Controls */}
        <div className="flex items-center justify-between pt-2 border-t border-slate-800/60">
          <button
            type="button"
            onClick={() => setShowOptions(!showOptions)}
            className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
          >
            <SlidersHorizontal className="w-3.5 h-3.5 text-slate-500" />
            <span>Traversal Parameters</span>
            <span className="text-[10px] text-slate-600">({showOptions ? 'Hide' : 'Configure'})</span>
          </button>

          <div className="flex items-center gap-2">
            {loading && onCancel && (
              <button
                type="button"
                onClick={onCancel}
                className="px-3.5 py-2 rounded-lg text-xs font-medium bg-slate-800 text-slate-300 hover:bg-slate-700 transition-colors flex items-center gap-1.5"
              >
                <XCircle className="w-4 h-4 text-rose-400" />
                <span>Cancel Request</span>
              </button>
            )}

            <button
              type="submit"
              disabled={!question.trim() || loading}
              className="px-5 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-slate-950 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center gap-2 shadow-lg shadow-cyan-950/40"
            >
              <Search className="w-4 h-4 text-slate-950" />
              <span>{loading ? 'Investigating...' : 'Investigate Query'}</span>
            </button>
          </div>
        </div>

        {/* Traversal Options Drawer */}
        {showOptions && (
          <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800/80 grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
            <div>
              <label className="text-[11px] text-slate-400 block mb-1">
                Max Hops Depth (1 to 3):
              </label>
              <input
                type="number"
                min={1}
                max={3}
                value={maxDepth}
                onChange={(e) => setMaxDepth(parseInt(e.target.value) || 3)}
                className="w-full bg-slate-900 border border-slate-800 rounded p-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="text-[11px] text-slate-400 block mb-1">
                Max Paths (1 to 20):
              </label>
              <input
                type="number"
                min={1}
                max={20}
                value={maxPaths}
                onChange={(e) => setMaxPaths(parseInt(e.target.value) || 10)}
                className="w-full bg-slate-900 border border-slate-800 rounded p-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="text-[11px] text-slate-400 block mb-1">
                Entity Hints (comma-separated):
              </label>
              <input
                type="text"
                placeholder="e.g. APT29, Cobalt Strike"
                value={hintsText}
                onChange={(e) => setHintsText(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded p-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>
        )}
      </form>
    </div>
  );
};
