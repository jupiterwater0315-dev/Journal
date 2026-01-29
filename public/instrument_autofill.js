/*
  instrument_autofill.js
  - Supports 2-level selection:
      1) instrumentType (CFD / FUTURES)  [optional]
      2) instrument
  - Autofills tickSize / tickValue, and contracts default.
  - If instrumentType is CFD, tickValue is editable (broker-specific).
  - Requires:
      window.__INSTRUMENT_SETS__ = { CFD: {...}, FUTURES: {...} }
    or:
      window.__INSTRUMENTS__ (legacy)
*/
(function () {
  const SETS = window.__INSTRUMENT_SETS__ || null;
  const LEGACY = window.__INSTRUMENTS__ || null;

  function qs(sel) { return document.querySelector(sel); }

  const typeSel = qs('select[name="instrumentType"]');
  const instrumentSel = qs('select[name="instrument"]');
  if (!instrumentSel) return;

  const tickSizeInput = qs('input[name="tickSize"]');
  const tickValueInput = qs('input[name="tickValue"]');
  const contractsInput = qs('input[name="contracts"]');

  function getType() {
    const t = String(typeSel ? typeSel.value : "").toUpperCase();
    return (t === "FUTURES") ? "FUTURES" : (t === "CFD" ? "CFD" : "");
  }

  function getMap() {
    const t = getType();
    if (SETS && t && SETS[t]) return SETS[t];
    if (LEGACY) return LEGACY;
    return null;
  }

  function rebuildInstrumentOptions() {
    if (!typeSel || !SETS) return;

    const t = getType();
    const map = (t && SETS[t]) ? SETS[t] : null;
    if (!map) return;

    const prev = instrumentSel.value;
    instrumentSel.innerHTML = Object.keys(map).map(k => {
      const label = (map[k] && map[k].label) ? map[k].label : k;
      return `<option value="${k}">${String(label)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")}</option>`;
    }).join("");

    // Restore selection if still available, else default to first key
    if (prev && map[prev]) instrumentSel.value = prev;
    else instrumentSel.value = Object.keys(map)[0] || "";
  }

  // If the user types contracts manually, do not overwrite it on subsequent instrument changes.
  if (contractsInput) {
    contractsInput.addEventListener('input', function () { contractsInput.dataset.autofill = '0'; });
    if (!contractsInput.dataset.autofill) contractsInput.dataset.autofill = '1';
  }

  function applyPreset() {
    const map = getMap();
    if (!map) return;

    const key = instrumentSel.value;
    const preset = map[key];
    if (!preset) return;

    if (tickSizeInput) tickSizeInput.value = String(preset.tickSize ?? '');

    if (tickValueInput) {
      // Only overwrite tickValue if (a) futures/readonly OR (b) empty
      const isFutures = (getType() === "FUTURES");
      tickValueInput.readOnly = isFutures;
      if (isFutures || !String(tickValueInput.value || '').trim()) {
        tickValueInput.value = String(preset.tickValue ?? '');
      }
    }

    if (contractsInput) {
      const allowOverwrite = (contractsInput.dataset.autofill === '1') || !String(contractsInput.value || '').trim();
      if (allowOverwrite) {
        contractsInput.value = String(preset.contractsDefault ?? 1);
        contractsInput.dataset.autofill = '1';
      }
    }
  }

  if (typeSel) {
    typeSel.addEventListener('change', function () {
      rebuildInstrumentOptions();
      applyPreset();
    });
  }

  instrumentSel.addEventListener('change', applyPreset);

  // Init
  rebuildInstrumentOptions();
  applyPreset();
})();
