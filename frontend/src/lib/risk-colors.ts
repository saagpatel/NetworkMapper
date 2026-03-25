export function riskColor(score: number): string {
  if (score >= 60) return 'var(--color-risk-high)';
  if (score >= 30) return 'var(--color-risk-medium)';
  return 'var(--color-risk-low)';
}

export function riskClass(score: number): string {
  if (score >= 60) return 'text-risk-high';
  if (score >= 30) return 'text-risk-medium';
  return 'text-risk-low';
}

export function riskBgClass(score: number): string {
  if (score >= 60) return 'bg-risk-high/20 text-risk-high';
  if (score >= 30) return 'bg-risk-medium/20 text-risk-medium';
  return 'bg-risk-low/20 text-risk-low';
}

export function riskLabel(score: number): string {
  if (score >= 60) return 'High';
  if (score >= 30) return 'Medium';
  return 'Low';
}

export function severityColor(severity: string): string {
  switch (severity) {
    case 'CRITICAL': return '#dc2626';
    case 'HIGH': return '#ef4444';
    case 'MEDIUM': return '#eab308';
    case 'LOW': return '#22c55e';
    default: return '#94a3b8';
  }
}
