import type { CheckStatus } from '../../types';

const badgeStyles: Record<CheckStatus, string> = {
  pass: 'bg-status-success/15 text-status-success dark:bg-status-success/20 dark:text-status-success',
  warn: 'bg-status-warning/15 text-status-warning dark:bg-status-warning/20 dark:text-status-warning',
  fail: 'bg-status-danger/15 text-status-danger dark:bg-status-danger/20 dark:text-status-danger',
};

interface StatusBadgeProps {
  status: CheckStatus;
  label: string;
}

/**
 * Small pill badge for PASS / WARN / FAIL with status-appropriate color tokens.
 */
export default function StatusBadge({ status, label }: StatusBadgeProps) {
  return (
    <span
      className={`inline-flex items-center rounded-pill px-2 py-0.5
                  text-caps-label uppercase ${badgeStyles[status]}`}
    >
      {label}
    </span>
  );
}
