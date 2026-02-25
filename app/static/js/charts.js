/**
 * F28 - Chart.js rendering utilities for DNS Watcher.
 *
 * Provides two rendering modes:
 *   1. renderHistoryChart(canvasId, labels, data)
 *      - Renders from inline template data (used by domain_history.html)
 *   2. renderHistoryChartFromApi(canvasId, domainId)
 *      - Fetches data from /api/v1/domains/<id>/history and renders
 *
 * Both produce a stacked bar chart with OK (green), Warning (amber),
 * Critical (red) segments. Responsive and mobile-friendly.
 */

/* global Chart */

const STATUS_COLORS = {
  ok:       { bg: "rgba(25, 135, 84, 0.8)",  border: "rgb(25, 135, 84)" },
  warning:  { bg: "rgba(253, 126, 20, 0.8)", border: "rgb(253, 126, 20)" },
  critical: { bg: "rgba(220, 53, 69, 0.8)",  border: "rgb(220, 53, 69)" },
  pending:  { bg: "rgba(108, 117, 125, 0.5)", border: "rgb(108, 117, 125)" },
  error:    { bg: "rgba(220, 53, 69, 0.5)",  border: "rgb(220, 53, 69)" },
};

/**
 * Map a status string to a numeric value for the chart.
 *   ok=1, warning=2, critical/error=3, pending/other=0
 */
function statusToValue(status) {
  switch (status) {
    case "ok":       return 1;
    case "warning":  return 2;
    case "critical": return 3;
    case "error":    return 3;
    default:         return 0;
  }
}

/**
 * Get background color for a status value.
 */
function statusColor(status) {
  return STATUS_COLORS[status] || STATUS_COLORS.pending;
}

/**
 * Render a stacked bar chart from inline template data.
 *
 * @param {string} canvasId - The id of the canvas element.
 * @param {string[]} labels - Date/time labels for the x-axis.
 * @param {Object[]} data - Array of objects with {overall, spf, dmarc, dkim, reputation}.
 */
function renderHistoryChart(canvasId, labels, data) {
  const canvas = document.getElementById(canvasId);
  if (!canvas || typeof Chart === "undefined") return;

  // Build stacked bar datasets: each bar has segments for each check type
  const checkTypes = ["spf", "dmarc", "dkim", "reputation"];
  const checkColors = {
    spf:        { ok: "rgba(25,135,84,0.9)",  warn: "rgba(253,126,20,0.9)", crit: "rgba(220,53,69,0.9)", pending: "rgba(108,117,125,0.4)" },
    dmarc:      { ok: "rgba(25,135,84,0.7)",  warn: "rgba(253,126,20,0.7)", crit: "rgba(220,53,69,0.7)", pending: "rgba(108,117,125,0.3)" },
    dkim:       { ok: "rgba(25,135,84,0.5)",  warn: "rgba(253,126,20,0.5)", crit: "rgba(220,53,69,0.5)", pending: "rgba(108,117,125,0.2)" },
    reputation: { ok: "rgba(25,135,84,0.35)", warn: "rgba(253,126,20,0.35)", crit: "rgba(220,53,69,0.35)", pending: "rgba(108,117,125,0.15)" },
  };

  // Simpler approach: one stacked bar per check with overall status coloring
  const okData = data.map(d => d.overall === "ok" ? 1 : 0);
  const warnData = data.map(d => d.overall === "warning" ? 1 : 0);
  const critData = data.map(d => (d.overall === "critical" || d.overall === "error") ? 1 : 0);
  const pendingData = data.map(d => (d.overall === "pending" || !d.overall) ? 1 : 0);

  new Chart(canvas, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [
        {
          label: "OK",
          data: okData,
          backgroundColor: STATUS_COLORS.ok.bg,
          borderColor: STATUS_COLORS.ok.border,
          borderWidth: 1,
        },
        {
          label: "Warning",
          data: warnData,
          backgroundColor: STATUS_COLORS.warning.bg,
          borderColor: STATUS_COLORS.warning.border,
          borderWidth: 1,
        },
        {
          label: "Critical",
          data: critData,
          backgroundColor: STATUS_COLORS.critical.bg,
          borderColor: STATUS_COLORS.critical.border,
          borderWidth: 1,
        },
        {
          label: "Pending",
          data: pendingData,
          backgroundColor: STATUS_COLORS.pending.bg,
          borderColor: STATUS_COLORS.pending.border,
          borderWidth: 1,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "top",
          labels: { usePointStyle: true, padding: 15 },
        },
        tooltip: {
          callbacks: {
            title: function(context) {
              return context[0].label;
            },
            afterBody: function(context) {
              const idx = context[0].dataIndex;
              const d = data[idx];
              if (!d) return "";
              return [
                "SPF: " + (d.spf || "n/a"),
                "DMARC: " + (d.dmarc || "n/a"),
                "DKIM: " + (d.dkim || "n/a"),
                "Reputation: " + (d.reputation || "n/a"),
              ];
            },
          },
        },
      },
      scales: {
        x: {
          stacked: true,
          ticks: {
            maxRotation: 45,
            autoSkip: true,
            maxTicksLimit: 15,
            font: { size: 11 },
          },
        },
        y: {
          stacked: true,
          beginAtZero: true,
          max: 1,
          ticks: { display: false },
          grid: { display: false },
        },
      },
    },
  });
}

/**
 * Fetch history data from the API and render a chart.
 *
 * @param {string} canvasId - The id of the canvas element.
 * @param {number} domainId - The domain ID to fetch history for.
 * @param {number} [limit=30] - Number of data points to fetch.
 */
async function renderHistoryChartFromApi(canvasId, domainId, limit) {
  limit = limit || 30;
  const canvas = document.getElementById(canvasId);
  if (!canvas || typeof Chart === "undefined") return;

  try {
    const response = await fetch(
      "/api/v1/domains/" + domainId + "/history?limit=" + limit
    );
    if (!response.ok) return;
    const json = await response.json();

    const labels = json.labels || [];
    const datasets = json.datasets || {};

    new Chart(canvas, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [
          {
            label: "OK",
            data: datasets.ok || [],
            backgroundColor: STATUS_COLORS.ok.bg,
            borderColor: STATUS_COLORS.ok.border,
            borderWidth: 1,
          },
          {
            label: "Warning",
            data: datasets.warning || [],
            backgroundColor: STATUS_COLORS.warning.bg,
            borderColor: STATUS_COLORS.warning.border,
            borderWidth: 1,
          },
          {
            label: "Critical",
            data: datasets.critical || [],
            backgroundColor: STATUS_COLORS.critical.bg,
            borderColor: STATUS_COLORS.critical.border,
            borderWidth: 1,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "top",
            labels: { usePointStyle: true, padding: 15 },
          },
          tooltip: {
            callbacks: {
              title: function(context) {
                return context[0].label;
              },
            },
          },
        },
        scales: {
          x: {
            stacked: true,
            ticks: {
              maxRotation: 45,
              autoSkip: true,
              maxTicksLimit: 15,
              font: { size: 11 },
            },
          },
          y: {
            stacked: true,
            beginAtZero: true,
            max: 1,
            ticks: { display: false },
            grid: { display: false },
          },
        },
      },
    });
  } catch (err) {
    console.error("Failed to render history chart:", err);
  }
}
