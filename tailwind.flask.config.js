/** @type {import('tailwindcss').Config} */
const colors = require('./data/config/colors');

module.exports = {
  content: [
    './app/templates/**/*.html',
    './app/static/js/**/*.js',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      /* ── Color tokens ────────────────────────────────────────────────── */
      colors: {
        primary:   colors.primary,
        secondary: colors.secondary,
        status:    colors.status,

        /* Surface / background tokens (dark-mode defaults) */
        surface: {
          bg0:     colors.dark.bg0,
          bg1:     colors.dark.bg1,
          card:    colors.dark.surface0,
          raised:  colors.dark.surface1,
          border:  colors.dark.border,
        },

        /* Light-mode surface overrides */
        'light-surface': {
          bg0:     colors.light.bg0,
          bg1:     colors.light.bg1,
          card:    colors.light.surface0,
          raised:  colors.light.surface1,
          border:  colors.light.border,
        },

        /* Semantic text tokens */
        content: {
          primary:   colors.dark.textPrimary,
          secondary: colors.dark.textSecondary,
          muted:     colors.dark.textMuted,
        },
        'light-content': {
          primary:   colors.light.textPrimary,
          secondary: colors.light.textSecondary,
          muted:     colors.light.textMuted,
        },

        accent: {
          glass:   colors.accent.glassHighlight,
          shadow:  colors.accent.shadow,
          chip:    colors.accent.chipFill,
        },
      },

      /* ── Font family ─────────────────────────────────────────────────── */
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
      },

      /* ── Border radius tokens ────────────────────────────────────────── */
      borderRadius: {
        container: '1.75rem',
        card:      '0.875rem',
        pill:      '9999px',
      },

      /* ── Box shadow tokens ──────────────────────────────────────────── */
      boxShadow: {
        ambient:      '0 8px 40px -8px rgba(0, 0, 0, 0.45)',
        'ambient-lg': '0 16px 64px -12px rgba(0, 0, 0, 0.5)',
        glass:        '0 4px 24px -4px rgba(0, 0, 0, 0.3), inset 0 1px 0 0 rgba(255, 255, 255, 0.06)',
      },

      /* ── Spacing ────────────────────────────────────────────────────── */
      spacing: {
        4.5: '1.125rem',
        7:   '1.75rem',
      },

      /* ── Font size presets ──────────────────────────────────────────── */
      fontSize: {
        'display-sm': ['2.25rem',  { lineHeight: '0.95', letterSpacing: '-0.02em', fontWeight: '500' }],
        'display-md': ['3rem',     { lineHeight: '0.95', letterSpacing: '-0.02em', fontWeight: '500' }],
        'title':      ['1.5rem',   { lineHeight: '1.05', letterSpacing: '-0.01em', fontWeight: '650' }],
        'caps-label': ['0.625rem', { lineHeight: '1.4',  letterSpacing: '0.08em',  fontWeight: '700' }],
      },
    },
  },
  plugins: [],
};
