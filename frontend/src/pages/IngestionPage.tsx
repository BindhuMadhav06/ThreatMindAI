import React, { useState } from 'react';
import { IngestionForm } from '../components/ingestion/IngestionForm';
import { IngestionResult } from '../components/ingestion/IngestionResult';
import { IngestionResponse } from '../types/api';
import { ingestDocument } from '../api/ingestion';
import { parseApiError } from '../api/client';
import { AlertCircle } from 'lucide-react';

export const IngestionPage: React.FC = () => {
  const [result, setResult] = useState<IngestionResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleIngest = async (formData: any) => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await ingestDocument(formData);
      setResult(data);
    } catch (err) {
      setError(parseApiError(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <IngestionForm onSubmit={handleIngest} loading={loading} />

      {error && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-900/80 text-rose-300 text-xs flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          <div>
            <h4 className="font-semibold text-rose-200">Ingestion Execution Error</h4>
            <p className="mt-0.5 leading-relaxed">{error}</p>
          </div>
        </div>
      )}

      {result && <IngestionResult result={result} />}
    </div>
  );
};
