import { Badge } from '@/components/ui/badge';
import type { RiskLevel } from '@/types/lucentid';

export function RiskBadge({ risk }: { risk: RiskLevel | string }) {
  if (risk === 'critical' || risk === 'high') {
    return <Badge variant="danger">{risk}</Badge>;
  }
  if (risk === 'elevated' || risk === 'guarded') {
    return <Badge variant="warning">{risk}</Badge>;
  }
  return <Badge variant="success">{risk || 'low'}</Badge>;
}
