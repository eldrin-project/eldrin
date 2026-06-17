import { useState, useEffect, useCallback, useRef } from 'react';
import { useAuthHeaders } from '@eldrin-project/eldrin-app-react';
import { toast } from 'sonner';
import type { EmployeeRow } from '../../types/factorial';
import * as api from '../../api';

export function EmployeeList({ apiBase }: { apiBase: string }) {
  const authHeaders = useAuthHeaders();
  const headersRef = useRef(authHeaders);
  headersRef.current = authHeaders;

  const [employees, setEmployees] = useState<EmployeeRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchEmployees = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await api.listEmployees(apiBase, headersRef.current);
      setEmployees(result.employees);
    } catch (e) {
      const message = e instanceof Error ? e.message : 'Failed to load employees';
      setError(message);
      toast.error(message);
    } finally {
      setLoading(false);
    }
  }, [apiBase]);

  useEffect(() => { void fetchEmployees(); }, [fetchEmployees]);

  if (loading) {
    return (
      <div className="flex justify-center items-center h-full py-16">
        <span className="loading loading-spinner loading-md" />
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

  if (employees.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-base-content/50">
        <h3 className="text-lg font-medium mb-1">No employees found</h3>
        <p className="text-sm">Run a sync in Settings to import employees from Factorial.</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex-shrink-0 px-4 sm:px-6 pt-4 pb-3 border-b border-base-300">
        <h2 className="text-xl font-semibold">Employees</h2>
        <p className="text-sm text-base-content/60 mt-0.5">{employees.length} employee{employees.length !== 1 ? 's' : ''}</p>
      </div>

      <div className="flex-1 overflow-y-auto min-h-0 px-4 sm:px-6 py-4">
        <div className="overflow-x-auto">
          <table className="table table-zebra w-full">
            <thead>
              <tr>
                <th>Full Name</th>
                <th>Email</th>
                <th>Job Title</th>
              </tr>
            </thead>
            <tbody>
              {employees.map((employee) => (
                <tr key={employee.id}>
                  <td className="font-medium">{employee.fullName ?? '—'}</td>
                  <td className="text-base-content/70">{employee.email ?? '—'}</td>
                  <td className="text-base-content/70">{employee.jobTitle ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
