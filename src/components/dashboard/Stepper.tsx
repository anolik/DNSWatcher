import type { StepData } from '../../types';

interface StepperProps {
  steps: StepData[];
}

const nodeStyles: Record<StepData['state'], string> = {
  complete: 'bg-primary-600 border-primary-400',
  current:  'bg-primary-400 border-primary-300 ring-2 ring-primary-400/30',
  upcoming: 'bg-surface-raised dark:bg-surface-raised bg-light-surface-raised border-surface-border/30',
};

const labelStyles: Record<StepData['state'], string> = {
  complete: 'text-light-content-muted dark:text-content-muted',
  current:  'text-light-content-primary dark:text-content-primary font-semibold',
  upcoming: 'text-light-content-muted dark:text-content-muted opacity-60',
};

const railSegment = (state: StepData['state']) =>
  state === 'upcoming'
    ? 'bg-surface-border/20 dark:bg-surface-border/20'
    : 'bg-primary-600/60 dark:bg-primary-600/60';

/**
 * 4-step progress indicator at the bottom of the container panel.
 * Responsive: full labels on lg+, compact on smaller screens.
 */
export default function Stepper({ steps }: StepperProps) {
  return (
    <div className="mt-8 pt-5 border-t border-light-surface-border/10 dark:border-surface-border/10">
      <div className="flex items-center">
        {steps.map((step, i) => (
          <div key={step.index} className="flex flex-1 items-center">
            {/* ── node ──────────────────────────────────── */}
            <div className="flex flex-col items-center gap-1.5">
              <div
                className={`flex h-3 w-3 rounded-full border
                            ${nodeStyles[step.state]}
                            transition-all`}
              />
              {/* index */}
              <span className="text-caps-label text-light-content-muted dark:text-content-muted opacity-60">
                {step.index}
              </span>
              {/* label — hidden on very small, visible on sm+ */}
              <span
                className={`hidden sm:block text-caps-label text-center
                            max-w-20 leading-tight ${labelStyles[step.state]}`}
              >
                {step.label}
              </span>
            </div>

            {/* ── rail segment (not after last) ─────────── */}
            {i < steps.length - 1 && (
              <div
                className={`mx-1 h-px flex-1 ${railSegment(step.state)} transition-colors`}
              />
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
