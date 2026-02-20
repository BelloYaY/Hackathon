import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

interface MetricCardProps {
  label: string;
  value: string | number;
  hint?: string;
  accent?: string;
}

export function MetricCard({ label, value, hint, accent }: MetricCardProps) {
  return (
    <Card className="min-h-[128px]">
      <CardHeader className="pb-2">
        <CardTitle className="panel-header">{label}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-semibold" style={accent ? { color: accent } : undefined}>
          {value}
        </div>
        {hint ? <div className="mt-2 text-xs text-muted-foreground">{hint}</div> : null}
      </CardContent>
    </Card>
  );
}
