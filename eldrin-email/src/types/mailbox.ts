export interface Mailbox {
  id: string;
  provider: 'gmail' | 'outlook' | 'imap';
  emailAddress: string;
  displayName: string | null;
  lastSyncAt: number | null;
  syncStatus: 'active' | 'paused' | 'error';
  syncDepth: 'full' | 'metadata' | 'thread_only';
  syncDays: number; // 0 = all
  errorMessage: string | null;
  createdAt: number;
  updatedAt: number;
}

export type SyncDepth = Mailbox['syncDepth'];
