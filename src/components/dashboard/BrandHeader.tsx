import ThemeSwitch from '../ThemeSwitch';

/**
 * Top bar: logo mark + brand name (left) and utility controls (right).
 */
export default function BrandHeader() {
  return (
    <header className="flex items-center justify-between">
      {/* ── logo + name ───────────────────────────────────── */}
      <div className="flex items-center gap-2.5">
        {/* circular logo mark */}
        <span
          className="flex h-7 w-7 items-center justify-center rounded-full
                     bg-gradient-to-br from-primary-400 to-primary-600
                     shadow-md"
        >
          <svg
            className="h-3.5 w-3.5 text-white"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={2.5}
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
        </span>

        <span
          className="text-sm font-medium tracking-wide
                     text-light-content-primary dark:text-content-primary"
        >
          MICA SPF tool
        </span>
      </div>

      {/* ── right controls ────────────────────────────────── */}
      <div className="flex items-center gap-3">
        <ThemeSwitch />

        {/* help icon */}
        <button
          type="button"
          aria-label="Help"
          className="flex h-7 w-7 items-center justify-center rounded-full
                     text-light-content-muted dark:text-content-muted
                     hover:text-light-content-primary dark:hover:text-content-primary
                     transition-colors"
        >
          <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
            <circle cx="12" cy="12" r="10" />
            <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
            <line x1="12" y1="17" x2="12.01" y2="17" />
          </svg>
        </button>

        {/* profile circle */}
        <span
          className="flex h-7 w-7 items-center justify-center rounded-full
                     bg-primary-600 text-xs font-semibold text-white"
        >
          P
        </span>
      </div>
    </header>
  );
}
