import BackgroundArcs from '../components/dashboard/BackgroundArcs';
import BrandHeader from '../components/dashboard/BrandHeader';
import HeroCopy from '../components/dashboard/HeroCopy';
import AppPreview from '../components/dashboard/AppPreview';
import Stepper from '../components/dashboard/Stepper';
import { sampleDomain, stepperData } from '../data/sampleData';

/**
 * /dashboard — Premium hero screen with embedded app preview.
 *
 * Layout:
 *  - Full-width gradient background with decorative arcs
 *  - Centered content container (dark translucent panel)
 *  - Two-column grid: hero copy (left) + app preview (right)
 *  - Stepper footer at the bottom
 *
 * Responsive:
 *  - base → sm: single column, stacked (hero → preview → stepper)
 *  - md+: two-column layout restored
 */
export default function Dashboard() {
  return (
    <div className="relative min-h-screen overflow-hidden
                    bg-light-surface-bg0 dark:bg-surface-bg0
                    transition-colors duration-300">
      {/* ── decorative background arcs ────────────────────── */}
      <BackgroundArcs />

      {/* ── centered content ──────────────────────────────── */}
      <div className="relative z-10 mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-7">
        {/* ── main container panel ────────────────────────── */}
        <div
          className="rounded-container
                     bg-light-surface-bg1/90 dark:bg-surface-bg1/80
                     backdrop-blur-md
                     border border-light-surface-border/15 dark:border-surface-border/10
                     shadow-ambient-lg
                     px-5 py-6 sm:px-7 sm:py-7"
        >
          {/* ── brand header ─────────────────────────────── */}
          <BrandHeader />

          {/* ── two-column grid ──────────────────────────── */}
          <div
            className="mt-8 grid grid-cols-1 items-center gap-8
                       lg:grid-cols-[1.4fr_1fr] lg:gap-6"
          >
            {/* left: messaging / feature statement */}
            <HeroCopy />

            {/* right: embedded app preview */}
            <AppPreview data={sampleDomain} />
          </div>

          {/* ── stepper footer ───────────────────────────── */}
          <Stepper steps={stepperData} />
        </div>
      </div>
    </div>
  );
}
