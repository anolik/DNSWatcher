import type { StatusRowData } from '../../types';
import StatusBadge from './StatusBadge';

interface StatusRowProps {
  row: StatusRowData;
}

/**
 * A single SPF / DKIM / DMARC status line inside the primary card.
 */
export default function StatusRow({ row }: StatusRowProps) {
  return (
    <div className="flex items-start justify-between gap-3 py-2">
      <div className="flex flex-col gap-0.5">
        <div className="flex items-center gap-2">
          <span
            className="text-xs font-semibold
                       text-light-content-primary dark:text-content-primary"
          >
            {row.label}
          </span>
          <StatusBadge status={row.status} label={row.value} />
        </div>
        <span
          className="text-caps-label
                     text-light-content-muted dark:text-content-muted"
        >
          {row.detail}
        </span>
      </div>
    </div>
  );
}
