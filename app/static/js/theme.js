/**
 * MICA Theme Toggle — Dark / Light mode with localStorage persistence.
 *
 * Uses the same storage key ('mica-theme') and prefers-color-scheme
 * fallback as the React prototype.
 */
(function () {
  "use strict";

  var STORAGE_KEY = "mica-theme";

  function getInitialTheme() {
    var stored = localStorage.getItem(STORAGE_KEY);
    if (stored === "light" || stored === "dark") return stored;
    return window.matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark"
      : "light";
  }

  function applyTheme(theme) {
    var root = document.documentElement;
    root.classList.toggle("dark", theme === "dark");
    localStorage.setItem(STORAGE_KEY, theme);

    // Update toggle button icon
    var toggleBtn = document.getElementById("theme-toggle");
    if (toggleBtn) {
      var sunIcon = toggleBtn.querySelector(".icon-sun");
      var moonIcon = toggleBtn.querySelector(".icon-moon");
      if (sunIcon && moonIcon) {
        sunIcon.style.display = theme === "dark" ? "none" : "block";
        moonIcon.style.display = theme === "dark" ? "block" : "none";
      }
    }
  }

  // Apply immediately (also called from inline <script> in <head> for FOUC prevention)
  window.__micaTheme = getInitialTheme();
  applyTheme(window.__micaTheme);

  // Bind toggle button after DOM ready
  document.addEventListener("DOMContentLoaded", function () {
    applyTheme(window.__micaTheme);

    var toggleBtn = document.getElementById("theme-toggle");
    if (toggleBtn) {
      toggleBtn.addEventListener("click", function () {
        window.__micaTheme = window.__micaTheme === "dark" ? "light" : "dark";
        applyTheme(window.__micaTheme);
      });
    }
  });
})();
