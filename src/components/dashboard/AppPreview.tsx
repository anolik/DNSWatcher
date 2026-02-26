import type { DomainCheckData } from '../../types';
import { previewTabs } from '../../data/sampleData';
import PrimaryCard from './PrimaryCard';

interface AppPreviewProps {
  data: DomainCheckData;
}

/**
 * Phone-frame mock showing a representative internal screen of the SPF tool.
 * Contains: status bar → nav tabs → module header → primary card.
 */
export default function AppPreview({ data }: AppPreviewProps) {
  const activeTab = 'CHECKS';

  return (
    <div
      className="relative mx-auto w-full max-w-md overflow-hidden rounded-phone
                 bg-gradient-to-br from-primary-900 via-primary-800 to-primary-600
                 dark:from-primary-900 dark:via-primary-800 dark:to-primary-600
                 from-primary-100 via-primary-50 to-white
                 border border-light-surface-border/15 dark:border-surface-border/10
                 shadow-ambient-lg p-5"
    >
      {/* ── soft internal shading ──────────────────────────── */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0
                   bg-gradient-to-b from-white/5 to-transparent dark:from-white/5
                   from-primary-900/5"
      />

      {/* ── status bar ─────────────────────────────────────── */}
      <div className="relative flex items-center justify-between
                      text-caps-label text-light-content-muted dark:text-content-secondary
                      opacity-80 mb-4">
        <span>9:41</span>
        <div className="flex items-center gap-1">
          {/* signal icon */}
          <svg className="h-3 w-3" viewBox="0 0 16 16" fill="currentColor">
            <rect x="1" y="10" width="2" height="5" rx="0.5" />
            <rect x="5" y="7" width="2" height="8" rx="0.5" />
            <rect x="9" y="4" width="2" height="11" rx="0.5" />
            <rect x="13" y="1" width="2" height="14" rx="0.5" />
          </svg>
          {/* wifi icon */}
          <svg className="h-3 w-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
            <path d="M5 12.55a11 11 0 0 1 14.08 0" />
            <path d="M8.53 16.11a6 6 0 0 1 6.95 0" />
            <line x1="12" y1="20" x2="12.01" y2="20" />
          </svg>
          {/* battery icon */}
          <svg className="h-3 w-4" viewBox="0 0 20 12" fill="currentColor">
            <rect x="0" y="1" width="16" height="10" rx="2" fill="none" stroke="currentColor" strokeWidth="1.5" />
            <rect x="2" y="3" width="11" height="6" rx="1" />
            <rect x="17" y="4" width="2" height="4" rx="0.5" />
          </svg>
        </div>
      </div>

      {/* ── navigation tabs ────────────────────────────────── */}
      <div className="relative flex items-center justify-between mb-5">
        <div className="flex gap-3 sm:gap-5">
          {previewTabs.map((tab) => (
            <button
              key={tab}
              type="button"
              className={`text-caps-label uppercase transition-colors
                ${
                  tab === activeTab
                    ? 'text-light-content-primary dark:text-content-primary font-bold'
                    : 'text-light-content-muted dark:text-content-muted hover:text-light-content-secondary dark:hover:text-content-secondary'
                }`}
            >
              {tab}
            </button>
          ))}
        </div>

        {/* hamburger */}
        <button
          type="button"
          aria-label="Menu"
          className="text-light-content-secondary dark:text-content-secondary opacity-95"
        >
          <svg className="h-4.5 w-4.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
            <line x1="3" y1="6" x2="21" y2="6" />
            <line x1="3" y1="12" x2="21" y2="12" />
            <line x1="3" y1="18" x2="21" y2="18" />
          </svg>
        </button>
      </div>

      {/* ── module header row ──────────────────────────────── */}
      <div className="relative flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          {/* bolt/check icon */}
          <svg
            className="h-4 w-4 text-primary-400"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <polyline points="20 6 9 17 4 12" />
          </svg>
          <span
            className="text-xs font-medium
                       text-light-content-primary dark:text-content-primary opacity-[0.88]"
          >
            Checks
          </span>
        </div>

        <div className="flex items-center gap-2.5">
          {/* notification icon */}
          <button
            type="button"
            aria-label="Notifications"
            className="text-light-content-muted dark:text-content-muted opacity-80
                       hover:opacity-100 transition-opacity"
          >
            <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
              <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
              <path d="M13.73 21a2 2 0 0 1-3.46 0" />
            </svg>
          </button>
          {/* profile circle */}
          <span
            className="flex h-5 w-5 items-center justify-center rounded-full
                       bg-primary-400/20 text-primary-300
                       text-caps-label font-bold"
          >
            P
          </span>
        </div>
      </div>

      {/* ── primary card ───────────────────────────────────── */}
      <div className="relative">
        <PrimaryCard data={data} />
      </div>
    </div>
  );
}
