import { Send } from 'lucide-react';

export function SentList() {
  return (
    <div className="flex flex-col items-center justify-center py-24 text-base-content/50">
      <Send className="w-12 h-12 mb-4 opacity-30" />
      <h2 className="text-lg font-semibold mb-1">Sent</h2>
      <p className="text-sm">Sent emails will appear here once you start sending.</p>
    </div>
  );
}
