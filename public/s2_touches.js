(function () {
  const box = document.getElementById("touchesBox");
  const addBtn = document.getElementById("addTouchBtn");
  if (!box || !addBtn) return;

  function cleanupOrphanLabels() {
    // Remove legacy "Touch #n" label-only rows that create empty gaps / duplicates
    const fields = Array.from(box.querySelectorAll(".field"));
    fields.forEach((f) => {
      const hasInput = !!f.querySelector("input[name^='touch']");
      const lbl = f.querySelector("label");
      if (!hasInput && lbl && /^Touch\s*#\d+/i.test((lbl.textContent || "").trim())) {
        f.remove();
      }
    });

    // Also remove loose labels that are not part of a touch-field and have no nearby input
    const looseLabels = Array.from(box.querySelectorAll("label"));
    looseLabels.forEach((lbl) => {
      const text = (lbl.textContent || "").trim();
      if (!/^Touch\s*#\d+/i.test(text)) return;

      if (lbl.closest(".touch-field")) return;

      const parent = lbl.parentElement;
      if (!parent) return;

      const hasInputNear = !!parent.querySelector("input[name^='touch']");
      if (!hasInputNear) {
        (lbl.closest(".field") || lbl).remove();
      }
    });
  }

  // Build a consistent "touch-field" row for any existing input
  function wrapExistingInputs() {
    cleanupOrphanLabels();

    const inputs = Array.from(box.querySelectorAll("input[name^='touch']"));

    inputs.forEach((inp) => {
      // If already wrapped, skip
      const existingWrap = inp.closest(".touch-field");
      if (existingWrap) return;

      // Create wrapper
      const wrap = document.createElement("div");
      wrap.className = "field touch-field";

      // Label
      const label = document.createElement("label");
      label.textContent = "Touch";

      // Row
      const row = document.createElement("div");
      row.style.display = "flex";
      row.style.gap = "6px";
      row.style.alignItems = "center";

      // Keep the existing input element
      inp.removeAttribute("id");
      row.appendChild(inp);

      // Remove button placeholder (shown only for #4+)
      const rm = document.createElement("button");
      rm.type = "button";
      rm.className = "remove-touch";
      rm.title = "Remove";
      rm.textContent = "✕";
      rm.style.padding = "4px 8px";
      rm.style.borderRadius = "10px";
      row.appendChild(rm);

      wrap.appendChild(label);
      wrap.appendChild(row);

      // Replace original legacy container if possible
      const oldField = inp.closest(".field");
      if (oldField && oldField.parentElement === box) {
        box.replaceChild(wrap, oldField);
      } else {
        box.appendChild(wrap);
      }
    });
  }

  function renumber() {
    const wraps = Array.from(box.querySelectorAll(".touch-field"));
    wraps.forEach((w, idx) => {
      const n = idx + 1;
      const label = w.querySelector("label");
      const input = w.querySelector("input");
      const rm = w.querySelector(".remove-touch");

      if (label) label.textContent = `Touch #${n}`;
      if (input) {
        input.name = `touch${n}`;
        input.id = `touch${n}`;
      }

      if (rm) rm.style.display = n <= 3 ? "none" : "inline-block";
    });
  }

  function addTouch() {
    const current = box.querySelectorAll(".touch-field").length;
    const next = current + 1;

    const wrap = document.createElement("div");
    wrap.className = "field touch-field";

    const label = document.createElement("label");
    label.textContent = `Touch #${next}`;

    const row = document.createElement("div");
    row.style.display = "flex";
    row.style.gap = "6px";
    row.style.alignItems = "center";

    const input = document.createElement("input");
    input.name = `touch${next}`;
    input.id = `touch${next}`;
    input.value = "";

    const rm = document.createElement("button");
    rm.type = "button";
    rm.className = "remove-touch";
    rm.title = "Remove";
    rm.textContent = "✕";
    rm.style.padding = "4px 8px";
    rm.style.borderRadius = "10px";

    row.appendChild(input);
    row.appendChild(rm);

    wrap.appendChild(label);
    wrap.appendChild(row);
    box.appendChild(wrap);

    renumber();
  }

  addBtn.addEventListener("click", () => {
    wrapExistingInputs();
    addTouch();
  });

  box.addEventListener("click", (e) => {
    if (!e.target.classList.contains("remove-touch")) return;

    wrapExistingInputs();
    const wraps = Array.from(box.querySelectorAll(".touch-field"));
    if (wraps.length <= 3) return;

    const w = e.target.closest(".touch-field");
    if (w) w.remove();

    renumber();
  });

  // Init
  cleanupOrphanLabels();
  wrapExistingInputs();
  renumber();
})();