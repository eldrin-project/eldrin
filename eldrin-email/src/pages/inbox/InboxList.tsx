import { Inbox } from 'lucide-react';

export function InboxList() {
  return (
    <div className="flex flex-col items-center justify-center py-24 text-base-content/50">
      <Inbox className="w-12 h-12 mb-4 opacity-30" />
      <h2 className="text-lg font-semibold mb-1">Inbox</h2>
      <p className="text-sm">No emails yet. Connect a mailbox to get started.</p>
    </div>
  );
}
