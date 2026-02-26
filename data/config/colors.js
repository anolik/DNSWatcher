/**
 * MICA SPF Tool — Design Token Color System
 *
 * Two hue families (primary + secondary) plus grayscale + status accents.
 * Consumed by tailwind.config.js — never hardcode hex values in components.
 */

const colors = {
  /* ──────────────────────── Primary: violet / indigo ──────────────────────── */
  primary: {
    50:  '#EDE9FF',
    100: '#D5CCFF',
    200: '#B5A4FF',
    300: '#9579FF',
    400: '#6A4BFF',   // bright violet accent / glow
    500: '#5835D4',
    600: '#4C22A4',   // violet mid
    700: '#3E1B8A',
    800: '#331570',
    900: '#2B1B78',   // deep indigo base
    950: '#150C3D',
  },

  /* ──────────────────────── Secondary: amber / rose ──────────────────────── */
  secondary: {
    300: '#F0C88A',
    400: '#E3AD6A',
    500: '#D79A54',   // amber highlight
    600: '#B36B7A',   // rose transition
    700: '#944E62',
  },

  /* ──────────────────────── Grayscale (dark mode surfaces) ───────────────── */
  dark: {
    bg0:          '#0B0814',  // near-black navy canvas
    bg1:          '#120C24',  // container fill
    surface0:     '#17112B',  // card / glass base
    surface1:     '#211A3A',  // raised surface
    border:       '#6A6476',  // subtle border (use with low opacity)
    textPrimary:  '#E9E7EE',
    textSecondary:'#B2AEBB',
    textMuted:    '#8D8997',
  },

  /* ──────────────────────── Grayscale (light mode surfaces) ──────────────── */
  light: {
    bg0:          '#F7F7FB',
    bg1:          '#FFFFFF',
    surface0:     '#FFFFFF',
    surface1:     '#F0EEF5',
    border:       '#D4D0DE',
    textPrimary:  '#0B1020',
    textSecondary:'#4B5563',
    textMuted:    '#6B7280',
  },

  /* ──────────────────────── Status accents ────────────────────────────────── */
  status: {
    success: '#22C55E',
    warning: '#F59E0B',
    danger:  '#EF4444',
  },

  /* ──────────────────────── Accent / utility ─────────────────────────────── */
  accent: {
    glassHighlight: 'rgba(255, 255, 255, 0.06)',
    shadow:         'rgba(0, 0, 0, 0.45)',
    chipFill:       '#17112B',
  },
};

module.exports = colors;
