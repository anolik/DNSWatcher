/**
 * Lightweight modal component — replaces Bootstrap Modal.
 *
 * Usage:
 *   <div id="myModal" class="mica-modal hidden" role="dialog" aria-modal="true">
 *     <div class="mica-modal-backdrop"></div>
 *     <div class="mica-modal-content">…</div>
 *   </div>
 *
 * API:
 *   openModal(id, options)   — show the modal, options: { onOpen(modal, trigger) }
 *   closeModal(id)           — hide the modal
 *
 * Declarative:
 *   <button data-modal-open="myModal">Open</button>
 *   <button data-modal-close="myModal">Close</button>
 */
(function () {
  "use strict";

  var openModals = [];

  function trapFocus(modal) {
    var focusable = modal.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    if (focusable.length === 0) return;
    focusable[0].focus();
  }

  function openModal(id, options) {
    var modal = document.getElementById(id);
    if (!modal) return;

    options = options || {};
    modal.classList.remove("hidden");
    document.body.style.overflow = "hidden";
    openModals.push(id);

    // Fire onOpen callback
    if (typeof options.onOpen === "function") {
      options.onOpen(modal, options.trigger || null);
    }

    // Fire custom event
    var event = new CustomEvent("modal:open", {
      detail: { id: id, trigger: options.trigger || null },
    });
    modal.dispatchEvent(event);

    requestAnimationFrame(function () {
      trapFocus(modal);
    });
  }

  function closeModal(id) {
    var modal = document.getElementById(id);
    if (!modal) return;

    modal.classList.add("hidden");
    openModals = openModals.filter(function (m) { return m !== id; });

    if (openModals.length === 0) {
      document.body.style.overflow = "";
    }

    // Fire custom event
    var event = new CustomEvent("modal:close", { detail: { id: id } });
    modal.dispatchEvent(event);
  }

  // Delegate: open buttons
  document.addEventListener("click", function (e) {
    var openTrigger = e.target.closest("[data-modal-open]");
    if (openTrigger) {
      e.preventDefault();
      var id = openTrigger.getAttribute("data-modal-open");
      openModal(id, { trigger: openTrigger });
      return;
    }

    var closeTrigger = e.target.closest("[data-modal-close]");
    if (closeTrigger) {
      e.preventDefault();
      var closeId = closeTrigger.getAttribute("data-modal-close");
      closeModal(closeId);
      return;
    }

    // Backdrop click
    var backdrop = e.target.closest(".mica-modal-backdrop");
    if (backdrop) {
      var modal = backdrop.closest(".mica-modal");
      if (modal) closeModal(modal.id);
    }
  });

  // Escape → close topmost
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && openModals.length > 0) {
      closeModal(openModals[openModals.length - 1]);
    }
  });

  // Expose globally
  window.openModal = openModal;
  window.closeModal = closeModal;
})();
