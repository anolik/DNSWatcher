interface SideChipProps {
  label: string;
}

/**
 * Pill chip anchored to the right edge of the card (e.g. "PROD").
 */
export default function SideChip({ label }: SideChipProps) {
  return (
    <div
      className="absolute -right-3 top-1/2 -translate-y-1/2
                 flex items-center gap-1.5 rounded-pill
                 bg-accent-chip dark:bg-accent-chip
                 bg-light-surface-card dark:bg-accent-chip
                 border border-surface-border/20 dark:border-surface-border/20
                 px-2.5 py-1 shadow-md"
    >
      {/* shield dot */}
      <span className="h-1.5 w-1.5 rounded-full bg-status-success" />
      <span
        className="text-caps-label uppercase
                   text-light-content-primary dark:text-content-primary"
      >
        {label}
      </span>
    </div>
  );
}
