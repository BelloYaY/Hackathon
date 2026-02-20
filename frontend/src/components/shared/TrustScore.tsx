import { Progress } from '@/components/ui/progress';
import { cn } from '@/lib/utils';

interface TrustScoreProps {
  score: number;
  className?: string;
}

export function TrustScore({ score, className }: TrustScoreProps) {
  const safeScore = Number.isFinite(score) ? Math.max(0, Math.min(100, score)) : 0;

  const barClass =
    safeScore >= 80 ? 'bg-success' : safeScore >= 50 ? 'bg-warning' : 'bg-danger';

  return (
    <div className={cn('space-y-2', className)}>
      <div className="flex items-end justify-between">
        <span className="panel-header">Trust Score</span>
        <span className="font-mono text-lg font-semibold">{safeScore}</span>
      </div>
      <Progress value={safeScore} barClassName={barClass} />
    </div>
  );
}
