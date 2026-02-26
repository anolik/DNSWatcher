/**
 * Lightweight dropdown component — replaces Bootstrap Dropdown + Popper.js.
 *
 * Usage:
 *   <button data-dropdown-toggle="menuId">Toggle</button>
 *   <div id="menuId" class="dropdown-menu" role="menu">…</div>
 *
 * The menu is positioned below the trigger using getBoundingClientRect().
 * Closes on outside click and Escape key.
 */
(function () {
  "use strict";

  var activeDropdown = null;

  function positionMenu(trigger, menu) {
    var rect = trigger.getBoundingClientRect();
    var menuWidth = menu.offsetWidth || 192;

    // Position below the trigger, aligned right
    menu.style.position = "fixed";
    menu.style.top = rect.bottom + 4 + "px";

    // Prefer right-align (dropdown-menu-end behavior)
    var left = rect.right - menuWidth;
    if (left < 8) left = rect.left;
    menu.style.left = left + "px";
  }

  function openDropdown(trigger, menu) {
    if (activeDropdown) closeDropdown();

    menu.classList.remove("hidden");
    menu.classList.add("dropdown-open");
    positionMenu(trigger, menu);

    activeDropdown = { trigger: trigger, menu: menu };
    trigger.setAttribute("aria-expanded", "true");
  }

  function closeDropdown() {
    if (!activeDropdown) return;
    activeDropdown.menu.classList.add("hidden");
    activeDropdown.menu.classList.remove("dropdown-open");
    activeDropdown.trigger.setAttribute("aria-expanded", "false");
    activeDropdown = null;
  }

  // Delegate click on triggers
  document.addEventListener("click", function (e) {
    var trigger = e.target.closest("[data-dropdown-toggle]");

    if (trigger) {
      e.preventDefault();
      e.stopPropagation();
      var menuId = trigger.getAttribute("data-dropdown-toggle");
      var menu = document.getElementById(menuId);
      if (!menu) return;

      if (activeDropdown && activeDropdown.menu === menu) {
        closeDropdown();
      } else {
        openDropdown(trigger, menu);
      }
      return;
    }

    // Click outside → close
    if (activeDropdown && !activeDropdown.menu.contains(e.target)) {
      closeDropdown();
    }
  });

  // Escape → close
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && activeDropdown) {
      closeDropdown();
      activeDropdown = null;
    }
  });

  // Expose for programmatic use
  window.MicaDropdown = {
    close: closeDropdown,
  };
})();
