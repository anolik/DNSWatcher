/**
 * Dashboard — client-side per-column filtering, column sorting, and auto-refresh.
 *
 * Features:
 *   - Per-column filters: text inputs for text/date columns, dropdowns for status columns
 *   - Click any column header to sort ascending/descending
 *   - "Clear filters" button resets all filters at once
 *   - Filter and sort state persisted in URL query parameters across page refreshes
 *   - Auto-refresh polling every 60 s via /api/v1/dashboard/summary
 */

(function () {
  "use strict";

  // =========================================================================
  // 0. URL STATE PERSISTENCE HELPERS
  // =========================================================================

  function getUrlParams() {
    return new URLSearchParams(window.location.search);
  }

  function setUrlParams(params) {
    var url = window.location.pathname;
    var qs = params.toString();
    if (qs) url += "?" + qs;
    window.history.replaceState(null, "", url);
  }

  // =========================================================================
  // 1. TABLE SORTING
  // =========================================================================

  const table = document.getElementById("domains-table");
  if (!table) return;

  const tbody = table.querySelector("tbody");
  const headers = table.querySelectorAll("th.sortable");

  const STATUS_ORDER = { ok: 0, warning: 1, critical: 2, error: 3, pending: 4 };

  let currentSortCol = -1;
  let currentSortAsc = true;

  function getCellValue(row, colIdx) {
    const cell = row.children[colIdx];
    if (!cell) return "";
    return (cell.getAttribute("data-value") || cell.textContent || "").trim().toLowerCase();
  }

  function compareRows(a, b, colIdx, sortType, asc) {
    var valA = getCellValue(a, colIdx);
    var valB = getCellValue(b, colIdx);
    var result = 0;

    if (sortType === "status") {
      var sA = STATUS_ORDER[valA] !== undefined ? STATUS_ORDER[valA] : 99;
      var sB = STATUS_ORDER[valB] !== undefined ? STATUS_ORDER[valB] : 99;
      result = sA - sB;
    } else if (sortType === "date") {
      if (!valA && !valB) result = 0;
      else if (!valA) result = 1;
      else if (!valB) result = -1;
      else result = valA.localeCompare(valB);
    } else {
      if (!valA && !valB) result = 0;
      else if (!valA || valA === "-") result = 1;
      else if (!valB || valB === "-") result = -1;
      else result = valA.localeCompare(valB);
    }

    return asc ? result : -result;
  }

  function sortTable(colIdx, sortType) {
    if (currentSortCol === colIdx) {
      currentSortAsc = !currentSortAsc;
    } else {
      currentSortCol = colIdx;
      currentSortAsc = true;
    }

    var rows = Array.from(tbody.querySelectorAll("tr"));
    rows.sort(function (a, b) {
      return compareRows(a, b, colIdx, sortType, currentSortAsc);
    });

    rows.forEach(function (row) {
      tbody.appendChild(row);
    });

    headers.forEach(function (th, i) {
      var icon = th.querySelector(".sort-icon");
      if (!icon) return;
      if (i === colIdx) {
        icon.className = currentSortAsc
          ? "bi bi-chevron-up sort-icon"
          : "bi bi-chevron-down sort-icon";
      } else {
        icon.className = "bi bi-chevron-expand sort-icon";
      }
    });

    // Persist sort state to URL
    saveSortToUrl();
  }

  function saveSortToUrl() {
    var params = getUrlParams();
    if (currentSortCol >= 0) {
      params.set("sort", currentSortCol);
      params.set("dir", currentSortAsc ? "asc" : "desc");
    } else {
      params.delete("sort");
      params.delete("dir");
    }
    setUrlParams(params);
  }

  headers.forEach(function (th, i) {
    th.style.cursor = "pointer";
    th.style.userSelect = "none";
    th.addEventListener("click", function () {
      sortTable(i, th.getAttribute("data-sort") || "text");
    });
  });

  // =========================================================================
  // 2. PER-COLUMN FILTERS
  // =========================================================================

  var filterInputs = table.querySelectorAll(".col-filter");
  var visibleCountEl = document.getElementById("visible-count");
  var clearBtn = document.getElementById("clear-filters");

  function applyFilters() {
    // Gather all filter values
    var filters = {};
    var hasActiveFilter = false;

    filterInputs.forEach(function (el) {
      var col = parseInt(el.getAttribute("data-col"), 10);
      var val = (el.value || "").trim().toLowerCase();
      filters[col] = val;
      if (val) hasActiveFilter = true;
    });

    // Show/hide the clear button
    if (clearBtn) {
      clearBtn.style.display = hasActiveFilter ? "" : "none";
    }

    var rows = tbody.querySelectorAll("tr");
    var visible = 0;

    rows.forEach(function (row) {
      var show = true;

      for (var col in filters) {
        if (!filters[col]) continue;

        var cellValue = getCellValue(row, parseInt(col, 10));
        var filterVal = filters[col];

        // For select dropdowns (status columns): exact match
        var filterEl = table.querySelector('.col-filter[data-col="' + col + '"]');
        if (filterEl && filterEl.tagName === "SELECT") {
          if (cellValue !== filterVal) {
            show = false;
            break;
          }
        } else {
          // For text inputs: substring match
          if (cellValue.indexOf(filterVal) === -1) {
            show = false;
            break;
          }
        }
      }

      row.style.display = show ? "" : "none";
      if (show) visible++;
    });

    if (visibleCountEl) {
      visibleCountEl.textContent = visible;
    }

    // Show "no results" message when filters hide all rows (1D)
    var noResultsRow = document.getElementById("no-results-row");
    if (hasActiveFilter && visible === 0) {
      if (!noResultsRow) {
        noResultsRow = document.createElement("tr");
        noResultsRow.id = "no-results-row";
        var td = document.createElement("td");
        td.colSpan = 12;
        td.className = "text-center text-light-content-muted dark:text-content-muted py-3";
        td.innerHTML = '<i class="bi bi-funnel mr-1"></i>No domains match the current filters.';
        noResultsRow.appendChild(td);
        tbody.appendChild(noResultsRow);
      }
      noResultsRow.style.display = "";
    } else if (noResultsRow) {
      noResultsRow.style.display = "none";
    }

    // Persist filter state to URL
    saveFiltersToUrl();
  }

  function saveFiltersToUrl() {
    var params = getUrlParams();
    // Remove old filter params
    var keysToDelete = [];
    params.forEach(function (val, key) {
      if (key.indexOf("f") === 0 && key.length <= 3) {
        keysToDelete.push(key);
      }
    });
    keysToDelete.forEach(function (key) { params.delete(key); });

    // Add active filters
    filterInputs.forEach(function (el) {
      var col = el.getAttribute("data-col");
      var val = (el.value || "").trim();
      if (val) {
        params.set("f" + col, val);
      }
    });
    setUrlParams(params);
  }

  filterInputs.forEach(function (el) {
    var eventType = el.tagName === "SELECT" ? "change" : "input";
    el.addEventListener(eventType, applyFilters);
  });

  // Clear all filters
  if (clearBtn) {
    clearBtn.addEventListener("click", function () {
      filterInputs.forEach(function (el) {
        el.value = "";
      });
      applyFilters();
    });
  }

  // =========================================================================
  // 3. RESTORE STATE FROM URL ON PAGE LOAD
  // =========================================================================

  (function restoreState() {
    var params = getUrlParams();

    // Restore filters
    var hasRestoredFilter = false;
    filterInputs.forEach(function (el) {
      var col = el.getAttribute("data-col");
      var saved = params.get("f" + col);
      if (saved) {
        el.value = saved;
        hasRestoredFilter = true;
      }
    });
    if (hasRestoredFilter) {
      applyFilters();
    }

    // Restore sort
    var sortCol = params.get("sort");
    var sortDir = params.get("dir");
    if (sortCol !== null) {
      var colIdx = parseInt(sortCol, 10);
      var th = headers[colIdx];
      if (th) {
        currentSortCol = colIdx;
        currentSortAsc = sortDir === "asc";
        // Toggle once more because sortTable flips direction when same col
        currentSortAsc = !currentSortAsc;
        sortTable(colIdx, th.getAttribute("data-sort") || "text");
      }
    }
  })();

  // =========================================================================
  // 4. AUTO-REFRESH POLLING (existing F29 functionality)
  // =========================================================================

  var POLL_INTERVAL_MS = 60000;
  var API_URL = "/api/v1/dashboard/summary";
  var pollTimer = null;
  var isRefreshing = false;

  function startPolling() {
    if (pollTimer) return;
    pollTimer = setInterval(refreshDashboard, POLL_INTERVAL_MS);
  }

  function stopPolling() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  async function refreshDashboard() {
    if (isRefreshing) return;
    isRefreshing = true;
    try {
      await fetch(API_URL);
    } catch (err) {
      console.error("Dashboard refresh failed:", err);
    } finally {
      isRefreshing = false;
    }
  }

  function handleVisibilityChange() {
    if (document.hidden) {
      stopPolling();
    } else {
      refreshDashboard();
      startPolling();
    }
  }

  startPolling();
  document.addEventListener("visibilitychange", handleVisibilityChange);

  // =========================================================================
  // 5. DROPDOWN OVERFLOW FIX
  // =========================================================================
  // dropdown.js handles positioning via data-dropdown-toggle attributes.
  // Toggle the table wrapper overflow while a dropdown is open so the
  // absolutely-positioned menu is never clipped.

  var tableWrapper = table.closest(".overflow-x-auto");

  if (tableWrapper) {
    document.addEventListener("click", function (e) {
      var toggle = e.target.closest("[data-dropdown-toggle]");
      if (toggle && tableWrapper.contains(toggle)) {
        tableWrapper.style.overflow = "visible";
      }
    });
    // Restore overflow when any dropdown closes (outside click / Escape)
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && tableWrapper) {
        tableWrapper.style.overflow = "";
      }
    });
    document.addEventListener("click", function (e) {
      if (!e.target.closest("[data-dropdown-toggle]") && !e.target.closest(".absolute")) {
        tableWrapper.style.overflow = "";
      }
    });
  }

  // =========================================================================
  // 6. DELETE CONFIRMATION MODAL (1B)
  // =========================================================================

  var deleteModal = document.getElementById("deleteModal");
  if (deleteModal) {
    deleteModal.addEventListener("modal:open", function (event) {
      var trigger = event.detail && event.detail.trigger;
      if (!trigger) return;
      var domainName = trigger.getAttribute("data-domain-name");
      var deleteUrl = trigger.getAttribute("data-delete-url");
      document.getElementById("deleteModalDomain").textContent = domainName;
      document.getElementById("deleteModalForm").setAttribute("action", deleteUrl);
    });
  }

  // =========================================================================
  // 6. CHECK ALL LOADING FEEDBACK (1C)
  // =========================================================================

  var checkAllForm = document.getElementById("checkAllForm");
  if (checkAllForm) {
    checkAllForm.addEventListener("submit", function () {
      var btn = document.getElementById("checkAllBtn");
      if (btn) {
        btn.disabled = true;
        btn.innerHTML =
          '<svg class="animate-spin -ml-1 mr-1.5 h-4 w-4 inline-block" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path></svg>Checking\u2026';
      }
    });
  }
})();
