import type { DomainCheckData } from '../../types';
import StatusRow from './StatusRow';
import SideChip from './SideChip';

interface PrimaryCardProps {
  data: DomainCheckData;
}

/**
 * Glass card showing a domain's health summary:
 * domain name, large status message, SPF/DKIM/DMARC rows, footer meta.
 */
export default function PrimaryCard({ data }: PrimaryCardProps) {
  return (
    <div
      className="relative rounded-card p-4.5
                 bg-light-surface-card/80 dark:bg-surface-card/50
                 backdrop-blur-xl
                 border border-light-surface-border/15 dark:border-surface-border/10
                 shadow-glass"
    >
      {/* ── inner highlight (top edge) ──────────────────── */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-x-0 top-0 h-px
                   rounded-t-card bg-accent-glass"
      />

      {/* ── card header ─────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <span className="text-caps-label uppercase text-light-content-muted dark:text-content-muted opacity-70">
          Domain
        </span>
        {/* kebab menu */}
        <button
          type="button"
          aria-label="More options"
          className="flex h-5 w-5 items-center justify-center rounded
                     text-light-content-muted dark:text-content-muted opacity-80
                     hover:opacity-100 hover:ring-1 hover:ring-surface-border/30
                     transition-all"
        >
          <svg className="h-4 w-4" viewBox="0 0 24 24" fill="currentColor">
            <circle cx="12" cy="5" r="1.5" />
            <circle cx="12" cy="12" r="1.5" />
            <circle cx="12" cy="19" r="1.5" />
          </svg>
        </button>
      </div>

      {/* ── domain name ─────────────────────────────────── */}
      <h3 className="mt-1 text-title text-light-content-primary dark:text-content-primary">
        {data.domain}
      </h3>

      {/* ── status summary (large two-line) ──────────────── */}
      <p className="mt-3 text-status-lg text-light-content-primary dark:text-content-primary">
        {data.statusSummaryLine1}
        <br />
        {data.statusSummaryLine2}
      </p>

      {/* ── status rows ─────────────────────────────────── */}
      <div className="mt-4 divide-y divide-surface-border/10 dark:divide-surface-border/10">
        {data.rows.map((row) => (
          <StatusRow key={row.label} row={row} />
        ))}
      </div>

      {/* ── meta footer row ──────────────────────────────── */}
      <div className="mt-4 flex items-center justify-between gap-4 pt-3
                      border-t border-light-surface-border/10 dark:border-surface-border/10">
        {/* left: avatar + last checked */}
        <div className="flex items-center gap-2">
          <span
            className="flex h-6 w-6 items-center justify-center rounded-full
                       bg-primary-600/20 text-primary-400
                       text-caps-label font-bold"
          >
            M
          </span>
          <div className="flex flex-col">
            <span className="text-caps-label text-light-content-muted dark:text-content-muted opacity-85">
              Last checked
            </span>
            <span className="text-xs font-medium text-light-content-secondary dark:text-content-secondary">
              {data.lastChecked}
            </span>
          </div>
        </div>

        {/* right: next run + drift */}
        <div className="flex gap-4">
          <div className="flex flex-col items-end">
            <span className="text-caps-label text-light-content-muted dark:text-content-muted opacity-80">
              Next run
            </span>
            <span className="text-xs font-medium text-light-content-secondary dark:text-content-secondary">
              {data.nextRun}
            </span>
          </div>
          <div className="flex flex-col items-end">
            <span className="text-caps-label text-light-content-muted dark:text-content-muted opacity-80">
              Drift
            </span>
            <span className="text-xs font-medium text-light-content-secondary dark:text-content-secondary">
              {data.drift}
            </span>
          </div>
        </div>
      </div>

      {/* ── side chip (PROD) ─────────────────────────────── */}
      <SideChip label={data.envBadge} />

      {/* ── corner glyph (decorative) ────────────────────── */}
      <div
        aria-hidden
        className="pointer-events-none absolute bottom-3 right-3 opacity-[0.08]
                   dark:opacity-[0.06]"
      >
        <svg className="h-16 w-16 text-primary-400" viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth={1.5}>
          <circle cx="32" cy="32" r="28" strokeDasharray="6 4" />
          <path d="M32 12 v8 M32 44 v8 M12 32 h8 M44 32 h8" />
        </svg>
      </div>
    </div>
  );
}
