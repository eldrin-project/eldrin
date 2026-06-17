import { useState, useEffect, useCallback, useRef } from 'react';
import { useAuthHeaders } from '@eldrin-project/eldrin-app-react';
import { toast } from 'sonner';
import type { Team } from '../../types/factorial';
import * as api from '../../api';
import { isNotConfiguredError, NOT_CONFIGURED_HINT } from '../../lib/errors';

function renderTeamName(team: Team): string {
  if (typeof team.name === 'string' && team.name) return team.name;
  return '—';
}

function renderTeamId(team: Team): string {
  if (typeof team.id === 'string' && team.id) return team.id;
  if (typeof team.id === 'number') return String(team.id);
  return '—';
}

export function TeamList({ apiBase }: { apiBase: string }) {
  const authHeaders = useAuthHeaders();
  const headersRef = useRef(authHeaders);
  headersRef.current = authHeaders;

  const [teams, setTeams] = useState<Team[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notConfigured, setNotConfigured] = useState(false);

  const fetchTeams = useCallback(async () => {
    setLoading(true);
    setError(null);
    setNotConfigured(false);
    try {
      const result = await api.listTeams(apiBase, headersRef.current);
      setTeams(result.teams);
    } catch (e) {
      const message = e instanceof Error ? e.message : 'Failed to load teams';
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

  useEffect(() => { void fetchTeams(); }, [fetchTeams]);

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

  if (teams.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-base-content/50">
        <h3 className="text-lg font-medium mb-1">No teams found</h3>
        <p className="text-sm">Run a sync in Settings to import teams from Factorial.</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex-shrink-0 px-4 sm:px-6 pt-4 pb-3 border-b border-base-300">
        <h2 className="text-xl font-semibold">Teams</h2>
        <p className="text-sm text-base-content/60 mt-0.5">{teams.length} team{teams.length !== 1 ? 's' : ''}</p>
      </div>

      <div className="flex-1 overflow-y-auto min-h-0 px-4 sm:px-6 py-4">
        <div className="overflow-x-auto">
          <table className="table table-zebra w-full">
            <thead>
              <tr>
                <th>Name</th>
                <th>ID</th>
                <th>Data</th>
              </tr>
            </thead>
            <tbody>
              {teams.map((team, index) => (
                <tr key={renderTeamId(team) !== '—' ? renderTeamId(team) : index}>
                  <td className="font-medium">{renderTeamName(team)}</td>
                  <td className="text-base-content/70 font-mono text-sm">{renderTeamId(team)}</td>
                  <td className="text-base-content/50 text-sm max-w-xs truncate">
                    {JSON.stringify(team)}
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
