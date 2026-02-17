import { FileText } from 'lucide-react';

export function TemplateList() {
  return (
    <div className="flex flex-col items-center justify-center h-full text-base-content/50">
      <FileText className="w-12 h-12 mb-4 opacity-30" />
      <h2 className="text-lg font-semibold mb-1">Templates</h2>
      <p className="text-sm">Create reusable email templates with merge fields.</p>
    </div>
  );
}
