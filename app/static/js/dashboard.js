/**
 * F29 - Dashboard auto-refresh via polling.
 *
 * Polls /api/v1/dashboard/summary every 60 seconds and updates:
 *   - Status summary count cards
 *   - Visual refresh indicator
 *
 * Uses the Page Visibility API to stop polling when the tab is hidden,
 * and resumes when the tab becomes visible again.
 */

(function () {
  "use strict";

  const POLL_INTERVAL_MS = 60000; // 60 seconds
  const API_URL = "/api/v1/dashboard/summary";

  let pollTimer = null;
  let isRefreshing = false;

  // Map status keys to their card element IDs / selectors
  const STATUS_KEYS = ["ok", "warning", "critical", "pending"];

  /**
   * Create and inject a refresh indicator into the page header.
   */
  function createRefreshIndicator() {
    const header = document.querySelector("h2");
    if (!header) return null;

    let indicator = document.getElementById("refresh-indicator");
    if (indicator) return indicator;

    indicator = document.createElement("span");
    indicator.id = "refresh-indicator";
    indicator.className = "ms-2 badge bg-light text-muted";
    indicator.style.fontSize = "0.65em";
    indicator.style.transition = "opacity 0.3s";
    indicator.innerHTML = '<i class="bi bi-arrow-clockwise me-1"></i>Auto-refresh';
    header.appendChild(indicator);
    return indicator;
  }

  /**
   * Show a visual refresh-in-progress state.
   */
  function showRefreshing(indicator) {
    if (!indicator) return;
    indicator.className = "ms-2 badge bg-info text-white";
    indicator.innerHTML = '<i class="bi bi-arrow-repeat me-1 spinner-rotate"></i>Refreshing...';
  }

  /**
   * Show the idle/ready state after refresh completes.
   */
  function showIdle(indicator, timestamp) {
    if (!indicator) return;
    indicator.className = "ms-2 badge bg-light text-muted";
    const time = timestamp
      ? new Date(timestamp).toLocaleTimeString()
      : new Date().toLocaleTimeString();
    indicator.innerHTML =
      '<i class="bi bi-arrow-clockwise me-1"></i>Updated ' + time;
  }

  /**
   * Show an error state.
   */
  function showError(indicator) {
    if (!indicator) return;
    indicator.className = "ms-2 badge bg-danger text-white";
    indicator.innerHTML = '<i class="bi bi-exclamation-triangle me-1"></i>Refresh failed';
  }

  /**
   * Update the summary count cards on the dashboard.
   *
   * Looks for card elements by their status key. The dashboard template
   * renders cards in order: ok, warning, critical, pending. We identify
   * them by finding .card elements with the appropriate bg-* class.
   */
  function updateCounts(data) {
    const cardMapping = {
      ok: "success",
      warning: "warning",
      critical: "danger",
      pending: "secondary",
    };

    for (const [key, bgClass] of Object.entries(cardMapping)) {
      // Find card by its bg class
      const cards = document.querySelectorAll(".card.text-bg-" + bgClass);
      for (const card of cards) {
        const countEl = card.querySelector(".fs-2.fw-bold");
        if (countEl && data[key] !== undefined) {
          const oldVal = parseInt(countEl.textContent, 10);
          const newVal = data[key];
          countEl.textContent = newVal;

          // Flash effect on change
          if (oldVal !== newVal) {
            countEl.style.transition = "color 0.3s";
            countEl.style.color = "#fff";
            setTimeout(function () {
              countEl.style.color = "";
            }, 500);
          }
        }
      }
    }

    // Update the domain count in the card header if present
    const headerCount = document.querySelector(
      ".card-header span"
    );
    if (headerCount && data.total !== undefined) {
      const match = headerCount.textContent.match(
        /Monitored Domains \(\d+\)/
      );
      if (match) {
        headerCount.textContent = "Monitored Domains (" + data.total + ")";
      }
    }
  }

  /**
   * Fetch the dashboard summary and update the UI.
   */
  async function refreshDashboard() {
    if (isRefreshing) return;
    isRefreshing = true;

    const indicator = createRefreshIndicator();
    showRefreshing(indicator);

    try {
      const response = await fetch(API_URL);
      if (!response.ok) {
        showError(indicator);
        return;
      }
      const data = await response.json();
      updateCounts(data);
      showIdle(indicator, data.timestamp);
    } catch (err) {
      console.error("Dashboard refresh failed:", err);
      showError(indicator);
    } finally {
      isRefreshing = false;
    }
  }

  /**
   * Start the polling timer.
   */
  function startPolling() {
    if (pollTimer) return;
    pollTimer = setInterval(refreshDashboard, POLL_INTERVAL_MS);
  }

  /**
   * Stop the polling timer.
   */
  function stopPolling() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  /**
   * Handle tab visibility changes.
   * Stop polling when hidden, resume when visible.
   */
  function handleVisibilityChange() {
    if (document.hidden) {
      stopPolling();
    } else {
      // Refresh immediately when tab becomes visible, then resume polling
      refreshDashboard();
      startPolling();
    }
  }

  // ---------------------------------------------------------------------------
  // Initialization
  // ---------------------------------------------------------------------------

  // Only run on the dashboard page (look for the summary cards)
  if (document.querySelector(".card.text-bg-success")) {
    // Add CSS for the spinner animation
    const style = document.createElement("style");
    style.textContent =
      "@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }" +
      ".spinner-rotate { display: inline-block; animation: spin 1s linear infinite; }";
    document.head.appendChild(style);

    // Create the indicator
    createRefreshIndicator();
    showIdle(createRefreshIndicator(), null);

    // Start polling
    startPolling();

    // Listen for visibility changes
    document.addEventListener("visibilitychange", handleVisibilityChange);
  }
})();
