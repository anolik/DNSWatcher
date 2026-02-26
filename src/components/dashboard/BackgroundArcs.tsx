/**
 * Full-screen decorative gradient arcs behind all content.
 * Dark mode: saturated violet/indigo + warm amber/rose arcs.
 * Light mode: same shapes but greatly desaturated / lowered opacity.
 */
export default function BackgroundArcs() {
  return (
    <div aria-hidden className="pointer-events-none fixed inset-0 -z-10 overflow-hidden">
      {/* ── vignette overlay ──────────────────────────────────────── */}
      <div className="absolute inset-0 bg-gradient-to-b from-transparent via-transparent
                      to-surface-bg0/80 dark:to-surface-bg0/80
                      to-light-surface-bg0/40" />

      {/* ── left arc (primary) ────────────────────────────────────── */}
      <div
        className="absolute -left-1/4 top-1/4 h-[140%] w-[80%] rounded-full
                   bg-gradient-to-br from-primary-900 to-primary-600
                   opacity-20 dark:opacity-90 blur-3xl"
      />

      {/* ── upper-right arc (secondary warm glow) ─────────────────── */}
      <div
        className="absolute -right-1/4 -top-1/4 h-[90%] w-[70%] rounded-full
                   bg-gradient-to-bl from-secondary-500 to-secondary-600
                   opacity-10 dark:opacity-[0.85] blur-3xl"
      />

      {/* ── lower-right arc (primary deep) ────────────────────────── */}
      <div
        className="absolute -right-1/6 bottom-0 h-[80%] w-[60%] rounded-full
                   bg-gradient-to-tl from-primary-600 to-primary-900
                   opacity-15 dark:opacity-80 blur-3xl"
      />

      {/* ── faint diagonal streaks ────────────────────────────────── */}
      <div
        className="absolute inset-0 opacity-[0.04]"
        style={{
          backgroundImage:
            'repeating-linear-gradient(135deg, transparent, transparent 60px, currentColor 60px, currentColor 61px)',
        }}
      />
    </div>
  );
}
