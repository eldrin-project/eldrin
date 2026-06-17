import { useState, useEffect, useCallback, useRef } from 'react';
import { useAuthHeaders } from '@eldrin-project/eldrin-app-react';
import { toast } from 'sonner';
import type { TimeOff } from '../../types/factorial';
import * as api from '../../api';
import { isNotConfiguredError, NOT_CONFIGURED_HINT } from '../../lib/errors';

function renderField(record: TimeOff, field: string): string {
  const value = record[field];
  if (typeof value === 'string' && value) return value;
  if (typeof value === 'number') return String(value);
  return '—';
}

export function TimeOffList({ apiBase }: { apiBase: string }) {
  const authHeaders = useAuthHeaders();
  const headersRef = useRef(authHeaders);
  headersRef.current = authHeaders;

  const [timeoff, setTimeoff] = useState<TimeOff[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notConfigured, setNotConfigured] = useState(false);

  const fetchTimeoff = useCallback(async () => {
    setLoading(true);
    setError(null);
    setNotConfigured(false);
    try {
      const result = await api.listTimeoff(apiBase, headersRef.current);
      setTimeoff(result.timeoff);
    } catch (e) {
      const message = e instanceof Error ? e.message : 'Failed to load time off records';
      if (isNotConfiguredError(message)) {
        setNotConfigured(true);
      } else {
        setError(message);
        toast.error(message);
      }
    } finally {
      setLoading(false);
    }
  }, [apiBase]);

  useEffect(() => { void fetchTimeoff(); }, [fetchTimeoff]);

  if (loading) {
    return (
      <div className="flex justify-center items-center h-full py-16">
        <span className="loading loading-spinner loading-md" />
      </div>
    );
  }

  if (notConfigured) {
    return (
      <div className="p-6">
        <div className="alert alert-warning">
          <span>{NOT_CONFIGURED_HINT}</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6">
        <div className="alert alert-error">
          <span>{error}</span>
        </div>
      </div>
    );
  }

  if (timeoff.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-base-content/50">
        <h3 className="text-lg font-medium mb-1">No time off records found</h3>
        <p className="text-sm">Run a sync in Settings to import time off data from Factorial.</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex-shrink-0 px-4 sm:px-6 pt-4 pb-3 border-b border-base-300">
        <h2 className="text-xl font-semibold">Time Off</h2>
        <p className="text-sm text-base-content/60 mt-0.5">{timeoff.length} record{timeoff.length !== 1 ? 's' : ''}</p>
      </div>

      <div className="flex-1 overflow-y-auto min-h-0 px-4 sm:px-6 py-4">
        <div className="overflow-x-auto">
          <table className="table table-zebra w-full">
            <thead>
              <tr>
                <th>ID</th>
                <th>Employee ID</th>
                <th>Status</th>
                <th>Data</th>
              </tr>
            </thead>
            <tbody>
              {timeoff.map((record, index) => (
                <tr key={renderField(record, 'id') !== '—' ? renderField(record, 'id') : index}>
                  <td className="font-mono text-sm">{renderField(record, 'id')}</td>
                  <td className="text-base-content/70 font-mono text-sm">{renderField(record, 'employee_id')}</td>
                  <td className="text-base-content/70">{renderField(record, 'status')}</td>
                  <td className="text-base-content/50 text-sm max-w-xs truncate">
                    {JSON.stringify(record)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
