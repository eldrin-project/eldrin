export interface EmployeeRow {
  id: string;
  factorialId: string;
  fullName: string | null;
  email: string | null;
  jobTitle: string | null;
  teamId: string | null;
  syncedAt: number;
}

export interface ConnectionStatus {
  configured: boolean;
  baseUrl: string | null;
}

export type Team = Record<string, unknown>;

export type TimeOff = Record<string, unknown>;

export interface SyncResult {
  employees: number;
  projects: number;
}
