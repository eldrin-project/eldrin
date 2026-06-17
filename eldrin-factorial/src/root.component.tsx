export interface RootProps {
  manifest?: { baseUrl?: string };
}

export function Root(_props: RootProps) {
  return <div className="p-6">eldrin-factorial</div>;
}
