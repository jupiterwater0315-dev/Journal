/*
  instrument_autofill.js
  - Updates tickSize / tickValue (and optionally contractsDefault) immediately when instrument changes.
  - Requires window.__INSTRUMENTS__ to be injected by the server.
*/
(function () {
  const INSTR = window.__INSTRUMENTS__ || null;
  if (!INSTR) return;

  function qs(sel) {
    return document.querySelector(sel);
  }

  const instrumentSel = qs('select[name="instrument"]');
  if (!instrumentSel) return;

  const tickSizeInput = qs('input[name="tickSize"]');
  const tickValueInput = qs('input[name="tickValue"]');
  const contractsInput = qs('input[name="contracts"]');

  // If the user types contracts manually, do not overwrite it on subsequent instrument changes.
  if (contractsInput) {
    contractsInput.addEventListener('input', function () {
      contractsInput.dataset.autofill = '0';
    });
    if (!contractsInput.dataset.autofill) contractsInput.dataset.autofill = '1';
  }

  function applyPreset() {
    const key = instrumentSel.value;
    const preset = INSTR[key];
    if (!preset) return;

    if (tickSizeInput) tickSizeInput.value = String(preset.tickSize ?? '');
    if (tickValueInput) tickValueInput.value = String(preset.tickValue ?? '');

    if (contractsInput) {
      const allowOverwrite = (contractsInput.dataset.autofill === '1') || !String(contractsInput.value || '').trim();
      if (allowOverwrite) {
        contractsInput.value = String(preset.contractsDefault ?? 1);
        contractsInput.dataset.autofill = '1';
      }
    }
  }

  instrumentSel.addEventListener('change', applyPreset);
  // Ensure correct values even if the browser restores form state.
  applyPreset();
})();
