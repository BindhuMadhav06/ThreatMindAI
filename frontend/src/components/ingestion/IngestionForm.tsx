import React, { useState, useRef } from 'react';
import { UploadCloud, FileText, CheckCircle2, AlertCircle } from 'lucide-react';

interface IngestionFormProps {
  onSubmit: (formData: {
    file?: File;
    text_content?: string;
    title?: string;
    url?: string;
    publisher?: string;
    published_date?: string;
    source_type?: string;
  }) => void;
  loading: boolean;
}

const SUPPORTED_EXTENSIONS = ['pdf', 'html', 'htm', 'json', 'txt'];
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

export const IngestionForm: React.FC<IngestionFormProps> = ({ onSubmit, loading }) => {
  const [mode, setMode] = useState<'file' | 'text'>('file');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [textContent, setTextContent] = useState('');
  const [title, setTitle] = useState('');
  const [url, setUrl] = useState('');
  const [publisher, setPublisher] = useState('');
  const [publishedDate, setPublishedDate] = useState('');
  const [error, setError] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const validateAndSetFile = (file: File) => {
    setError(null);
    const ext = file.name.split('.').pop()?.toLowerCase();
    if (!ext || !SUPPORTED_EXTENSIONS.includes(ext)) {
      setError(`Unsupported file type '.${ext}'. Supported formats: PDF, HTML, JSON, TXT.`);
      return;
    }
    if (file.size > MAX_FILE_SIZE) {
      setError('File size exceeds the maximum 10MB limit.');
      return;
    }
    setSelectedFile(file);
    if (!title) {
      setTitle(file.name.replace(/\.[^/.]+$/, ''));
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (loading) return;
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (mode === 'file' && !selectedFile) {
      setError('Please select a CTI document file to upload.');
      return;
    }

    if (mode === 'text' && !textContent.trim()) {
      setError('Please provide raw CTI text content.');
      return;
    }

    onSubmit({
      file: mode === 'file' ? selectedFile || undefined : undefined,
      text_content: mode === 'text' ? textContent.trim() : undefined,
      title: title.trim() || undefined,
      url: url.trim() || undefined,
      publisher: publisher.trim() || undefined,
      published_date: publishedDate.trim() || undefined,
      source_type: mode === 'file' ? selectedFile?.name.split('.').pop()?.toLowerCase() : 'txt',
    });
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-5">
      {/* Mode Selector */}
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">Ingest Cyber Threat Intelligence</h2>
          <p className="text-[11px] text-slate-400">Extract entities, ground relationships, and persist into Neo4j</p>
        </div>
        <div className="flex rounded-lg bg-slate-950 p-1 border border-slate-800 text-xs">
          <button
            type="button"
            onClick={() => setMode('file')}
            className={`px-3 py-1 rounded font-medium transition-colors ${
              mode === 'file' ? 'bg-cyan-950 text-cyan-300 border border-cyan-800' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            File Upload
          </button>
          <button
            type="button"
            onClick={() => setMode('text')}
            className={`px-3 py-1 rounded font-medium transition-colors ${
              mode === 'text' ? 'bg-cyan-950 text-cyan-300 border border-cyan-800' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Raw Text
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-900/60 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        {mode === 'file' ? (
          <div>
            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-xl p-6 text-center cursor-pointer transition-colors ${
                selectedFile
                  ? 'border-cyan-500 bg-cyan-950/10'
                  : 'border-slate-800 bg-slate-950 hover:border-slate-700'
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".pdf,.html,.htm,.json,.txt"
                onChange={handleFileChange}
                className="hidden"
                disabled={loading}
              />
              <UploadCloud className="w-8 h-8 text-cyan-400 mx-auto mb-2" />
              {selectedFile ? (
                <div className="text-xs">
                  <span className="font-semibold text-slate-100">{selectedFile.name}</span>
                  <span className="text-slate-500 block">
                    {(selectedFile.size / 1024).toFixed(1)} KB — Click to change
                  </span>
                </div>
              ) : (
                <div className="text-xs">
                  <span className="text-slate-200 font-medium">Click to select or drag & drop CTI report</span>
                  <span className="text-slate-500 block mt-1">Supported: PDF, HTML, JSON, TXT (Max 10MB)</span>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div>
            <label className="text-[11px] font-semibold text-slate-300 uppercase tracking-wider block mb-1">
              CTI Advisory / Report Text
            </label>
            <textarea
              rows={6}
              value={textContent}
              onChange={(e) => setTextContent(e.target.value)}
              placeholder="Paste raw cybersecurity advisory content, threat report paragraphs, or IOC indicators..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              disabled={loading}
            />
          </div>
        )}

        {/* Source Metadata Fields */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
          <div>
            <label className="text-[11px] text-slate-400 block mb-1">Document Title (Optional):</label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g. APT29 Lateral Movement Analysis"
              className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
              disabled={loading}
            />
          </div>

          <div>
            <label className="text-[11px] text-slate-400 block mb-1">Source URL / Link (Optional):</label>
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://advisories.example.org/apt29-report"
              className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
              disabled={loading}
            />
          </div>

          <div>
            <label className="text-[11px] text-slate-400 block mb-1">Publisher Organization (Optional):</label>
            <input
              type="text"
              value={publisher}
              onChange={(e) => setPublisher(e.target.value)}
              placeholder="e.g. CISA, Mandiant, Microsoft Threat Intel"
              className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
              disabled={loading}
            />
          </div>

          <div>
            <label className="text-[11px] text-slate-400 block mb-1">Publication Date (YYYY-MM-DD):</label>
            <input
              type="date"
              value={publishedDate}
              onChange={(e) => setPublishedDate(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
              disabled={loading}
            />
          </div>
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full py-2.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-slate-950 disabled:opacity-50 transition-all flex items-center justify-center gap-2"
        >
          <UploadCloud className="w-4 h-4 text-slate-950" />
          <span>{loading ? 'Processing Document & Persisting to Graph...' : 'Process & Ingest Document'}</span>
        </button>
      </form>
    </div>
  );
};
