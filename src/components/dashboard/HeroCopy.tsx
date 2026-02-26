/**
 * Left-side messaging: two-line display headline + short supporting paragraph.
 */
export default function HeroCopy() {
  return (
    <div className="flex flex-col gap-5">
      {/* ── headline ──────────────────────────────────────── */}
      <h1
        className="text-display-sm md:text-display-md lg:text-display-lg
                   text-light-content-primary dark:text-content-primary
                   max-w-lg"
      >
        Monitor SPF, DKIM
        <br />
        and DMARC health.
      </h1>

      {/* ── supporting text ───────────────────────────────── */}
      <p
        className="max-w-xs text-xs leading-relaxed
                   text-light-content-secondary/75 dark:text-content-secondary/75"
      >
        Run daily automated checks on every domain you manage. Detect DNS
        record drift, compare expected vs.&nbsp;observed configurations, and
        trigger alerts the moment something changes.
      </p>
    </div>
  );
}
