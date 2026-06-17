import { useState, useEffect, useCallback } from 'react';
import { useAuthHeaders } from '@eldrin-project/eldrin-app-react';
import { toast } from 'sonner';
import * as api from '../../api';
import type { ConnectionStatus } from '../../types/factorial';

export function ConnectionSettings({ apiBase }: { apiBase: string }) {
  const headers = useAuthHeaders();
  const [status, setStatus] = useState<ConnectionStatus | null>(null);
  const [syncing, setSyncing] = useState(false);

  const load = useCallback(async () => {
    try { setStatus(await api.getConnection(apiBase, headers)); }
    catch (e) { toast.error(e instanceof Error ? e.message : 'Failed to load status'); }
  }, [apiBase, headers]);

  useEffect(() => { void load(); }, [load]);

  const sync = async () => {
    setSyncing(true);
    try {
      const r = await api.runSync(apiBase, headers);
      toast.success(`Synced ${r.employees} employees, ${r.projects} projects`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Sync failed');
    } finally { setSyncing(false); }
  };

  return (
    <div className="p-6 space-y-4">
      <h2 className="text-lg font-semibold">Factorial Connection</h2>
      {status === null ? <p>Loading…</p> : status.configured
        ? <p className="text-success">Connected to {status.baseUrl}</p>
        : <p className="text-error">Not configured. Set FACTORIAL_API_BASE_URL and FACTORIAL_API_KEY in app settings.</p>}
      <button className="btn btn-primary" disabled={!status?.configured || syncing} onClick={sync}>
        {syncing ? 'Syncing…' : 'Sync now'}
      </button>
    </div>
  );
}
