/**
 * DMARC Reports -- Pass/Fail Trend Chart.
 *
 * Fetches daily aggregates from /api/dmarc-reports/trends and renders
 * a Chart.js line chart.  Respects the active domain filter if present.
 */
(function () {
  "use strict";

  var canvas = document.getElementById("dmarc-trend-chart");
  if (!canvas) return;

  // Pick up the active domain filter from the select element
  var domainSelect = document.getElementById("domain-filter");
  var domain = domainSelect ? domainSelect.value : "";

  var url = "/api/dmarc-reports/trends";
  if (domain) url += "?domain=" + encodeURIComponent(domain);

  fetch(url, { credentials: "same-origin" })
    .then(function (res) {
      if (!res.ok) throw new Error("HTTP " + res.status);
      return res.json();
    })
    .then(function (data) {
      if (!data.labels || data.labels.length === 0) {
        // Hide the chart container when there is no data
        var wrapper = canvas.closest(".mica-card");
        if (wrapper) wrapper.style.display = "none";
        return;
      }

      // Detect dark mode
      var isDark = document.documentElement.classList.contains("dark");
      var gridColor = isDark ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.06)";
      var textColor = isDark ? "rgba(255,255,255,0.6)" : "rgba(0,0,0,0.5)";

      new Chart(canvas, {
        type: "line",
        data: {
          labels: data.labels,
          datasets: [
            {
              label: "Pass",
              data: data.pass,
              borderColor: "#22c55e",
              backgroundColor: "rgba(34,197,94,0.1)",
              fill: true,
              tension: 0.3,
              pointRadius: 3,
              pointHoverRadius: 5,
            },
            {
              label: "Fail",
              data: data.fail,
              borderColor: "#ef4444",
              backgroundColor: "rgba(239,68,68,0.1)",
              fill: true,
              tension: 0.3,
              pointRadius: 3,
              pointHoverRadius: 5,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: { mode: "index", intersect: false },
          plugins: {
            legend: {
              position: "top",
              labels: { color: textColor, usePointStyle: true, padding: 16 },
            },
            tooltip: { mode: "index", intersect: false },
          },
          scales: {
            x: {
              grid: { color: gridColor },
              ticks: { color: textColor, maxRotation: 45, maxTicksLimit: 15 },
            },
            y: {
              beginAtZero: true,
              grid: { color: gridColor },
              ticks: { color: textColor, precision: 0 },
            },
          },
        },
      });
    })
    .catch(function (err) {
      console.warn("DMARC trend chart error:", err);
    });
})();
