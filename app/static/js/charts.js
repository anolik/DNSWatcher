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
 * Supports dark mode via MICA design system tokens.
 */

/* global Chart */

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
  // Fallback for calls outside render functions
  var fallbackColors = {
    ok:       { bg: "rgba(34, 197, 94, 0.8)",  border: "#22C55E" },
    warning:  { bg: "rgba(245, 158, 11, 0.8)", border: "#F59E0B" },
    critical: { bg: "rgba(239, 68, 68, 0.8)",  border: "#EF4444" },
    pending:  { bg: "rgba(108, 117, 125, 0.5)", border: "rgb(108, 117, 125)" },
    error:    { bg: "rgba(239, 68, 68, 0.5)",  border: "#EF4444" },
  };
  return fallbackColors[status] || fallbackColors.pending;
}

/**
 * Render a stacked bar chart from inline template data.
 *
 * @param {string} canvasId - The id of the canvas element.
 * @param {string[]} labels - Date/time labels for the x-axis.
 * @param {Object[]} data - Array of objects with {overall, spf, dmarc, dkim, reputation}.
 */
function renderHistoryChart(canvasId, labels, data) {
  var canvas = document.getElementById(canvasId);
  if (!canvas || typeof Chart === "undefined") return;

  var isDark = document.documentElement.classList.contains('dark');

  var STATUS_COLORS = {
    ok:       { bg: isDark ? "rgba(34, 197, 94, 0.8)" : "rgba(34, 197, 94, 0.8)",   border: "#22C55E" },
    warning:  { bg: isDark ? "rgba(245, 158, 11, 0.8)" : "rgba(245, 158, 11, 0.8)", border: "#F59E0B" },
    critical: { bg: isDark ? "rgba(239, 68, 68, 0.8)" : "rgba(239, 68, 68, 0.8)",   border: "#EF4444" },
    pending:  { bg: isDark ? "rgba(141, 137, 151, 0.5)" : "rgba(108, 117, 125, 0.5)", border: isDark ? "#8D8997" : "rgb(108, 117, 125)" },
    error:    { bg: isDark ? "rgba(239, 68, 68, 0.5)" : "rgba(220, 53, 69, 0.5)",   border: "#EF4444" },
  };

  var textColor = isDark ? '#B2AEBB' : '#4B5563';
  var gridColor = isDark ? 'rgba(106, 100, 118, 0.2)' : 'rgba(0, 0, 0, 0.1)';

  // Simpler approach: one stacked bar per check with overall status coloring
  var okData = data.map(function(d) { return d.overall === "ok" ? 1 : 0; });
  var warnData = data.map(function(d) { return d.overall === "warning" ? 1 : 0; });
  var critData = data.map(function(d) { return (d.overall === "critical" || d.overall === "error") ? 1 : 0; });
  var pendingData = data.map(function(d) { return (d.overall === "pending" || !d.overall) ? 1 : 0; });

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
          labels: {
            usePointStyle: true,
            padding: 15,
            color: textColor,
          },
        },
        tooltip: {
          callbacks: {
            title: function(context) {
              return context[0].label;
            },
            afterBody: function(context) {
              var idx = context[0].dataIndex;
              var d = data[idx];
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
            color: textColor,
          },
          grid: {
            color: gridColor,
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
  var canvas = document.getElementById(canvasId);
  if (!canvas || typeof Chart === "undefined") return;

  var isDark = document.documentElement.classList.contains('dark');

  var STATUS_COLORS = {
    ok:       { bg: isDark ? "rgba(34, 197, 94, 0.8)" : "rgba(34, 197, 94, 0.8)",   border: "#22C55E" },
    warning:  { bg: isDark ? "rgba(245, 158, 11, 0.8)" : "rgba(245, 158, 11, 0.8)", border: "#F59E0B" },
    critical: { bg: isDark ? "rgba(239, 68, 68, 0.8)" : "rgba(239, 68, 68, 0.8)",   border: "#EF4444" },
    pending:  { bg: isDark ? "rgba(141, 137, 151, 0.5)" : "rgba(108, 117, 125, 0.5)", border: isDark ? "#8D8997" : "rgb(108, 117, 125)" },
    error:    { bg: isDark ? "rgba(239, 68, 68, 0.5)" : "rgba(220, 53, 69, 0.5)",   border: "#EF4444" },
  };

  var textColor = isDark ? '#B2AEBB' : '#4B5563';
  var gridColor = isDark ? 'rgba(106, 100, 118, 0.2)' : 'rgba(0, 0, 0, 0.1)';

  try {
    var response = await fetch(
      "/api/v1/domains/" + domainId + "/history?limit=" + limit
    );
    if (!response.ok) return;
    var json = await response.json();

    var apiLabels = json.labels || [];
    var datasets = json.datasets || {};

    new Chart(canvas, {
      type: "bar",
      data: {
        labels: apiLabels,
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
            labels: {
              usePointStyle: true,
              padding: 15,
              color: textColor,
            },
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
              color: textColor,
            },
            grid: {
              color: gridColor,
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
