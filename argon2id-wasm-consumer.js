/**
 * hash.js — Argon2id WASM Playground
 *
 * Self-contained: reads all parameters from the form, validates them,
 * calls argon2-browser (loaded from CDN as window.argon2), measures
 * wall-clock time with performance.now(), and displays results.
 *
 * No external dependencies beyond the CDN script already in index.html.
 */

(function () {
  'use strict';

  /* ── DOM refs ─────────────────────────────────────────────────────── */
  const $ = (id) => document.getElementById(id);

  const fPass    = $('f-pass');
  const fSalt    = $('f-salt');
  const fTime    = $('f-time');
  const fMem     = $('f-mem');
  const fPar     = $('f-par');
  const fLen     = $('f-len');
  const btn      = $('hash-btn');
  const outHex   = $('out-hex');
  const outEnc   = $('out-encoded');
  const outTime  = $('out-time');
  const statusEl = $('status');

  /* ── Helpers ──────────────────────────────────────────────────────── */

  function setStatus(html, type) {
    statusEl.innerHTML = html;
    statusEl.className = 'status ' + type;
  }

  function setLoading(on) {
    btn.disabled    = on;
    btn.textContent = on ? 'Computing…' : '⚡ Compute Hash';
  }

  /**
   * Read and validate all form fields.
   * Returns a params object or throws an Error with a human-readable message.
   */
  function readParams() {
    const pass = fPass.value;
    if (!pass) throw new Error('Value to hash must not be empty.');

    const saltStr = fSalt.value;
    if (saltStr.length < 8) throw new Error('Salt must be at least 8 characters.');

    // Encode salt string → Uint8Array via TextEncoder
    const salt = new TextEncoder().encode(saltStr);

    const time = parseInt(fTime.value, 10);
    if (!Number.isFinite(time) || time < 1 || time > 100)
      throw new Error('Iterations (t) must be between 1 and 100.');

    const mem = parseInt(fMem.value, 10);
    if (!Number.isFinite(mem) || mem < 1024)
      throw new Error('Memory (m) must be at least 1024 KiB.');

    const parallelism = parseInt(fPar.value, 10);
    if (!Number.isFinite(parallelism) || parallelism < 1 || parallelism > 16)
      throw new Error('Parallelism (p) must be between 1 and 16.');

    const hashLen = parseInt(fLen.value, 10);
    if (!Number.isFinite(hashLen) || hashLen < 4 || hashLen > 64)
      throw new Error('Hash length must be between 4 and 64 bytes.');

    return { pass, salt, time, mem, parallelism, hashLen };
  }

  /* ── Core hashing function ────────────────────────────────────────── */

  async function computeHash() {
    // 1. Validate library availability
    if (typeof argon2 === 'undefined') {
      setStatus('❌ <b>argon2</b> global not found — CDN script failed to load.', 'error');
      return;
    }

    // 2. Read & validate params
    let params;
    try {
      params = readParams();
    } catch (validationErr) {
      setStatus('⚠️ ' + validationErr.message, 'error');
      return;
    }

    // 3. Update UI to "loading" state
    setLoading(true);
    setStatus('<span class="spinner"></span>Computing Argon2id hash…', 'loading');
    outHex.textContent  = '…';
    outEnc.textContent  = '…';
    outTime.textContent = '…';

    // Yield to browser so the repaint happens before the heavy WASM work.
    await new Promise((r) => setTimeout(r, 0));

    // 4. Hash + measure time
    const t0 = performance.now();
    try {
      const result = await argon2.hash({
        pass:        params.pass,
        salt:        params.salt,
        time:        params.time,
        mem:         params.mem,
        parallelism: params.parallelism,
        hashLen:     params.hashLen,
        type:        argon2.ArgonType.Argon2id,
      });

      const elapsed = performance.now() - t0;

      // 5. Display results
      outHex.textContent  = result.hashHex;
      outEnc.textContent  = result.encoded;
      outTime.textContent = elapsed.toFixed(2) + ' ms';

      setStatus('✅ Hash computed successfully via WASM!', 'success');

      // Also log to console for easy copy-paste
      console.group('[argon2id] result');
      console.log('input      :', params.pass);
      console.log('salt (str) :', fSalt.value);
      console.log('t / m / p  :', params.time, '/', params.mem, '/', params.parallelism);
      console.log('hashLen    :', params.hashLen);
      console.log('hashHex    :', result.hashHex);
      console.log('encoded    :', result.encoded);
      console.log('time       :', elapsed.toFixed(2), 'ms');
      console.groupEnd();

    } catch (err) {
      const elapsed = performance.now() - t0;
      outHex.textContent  = 'Error';
      outEnc.textContent  = 'Error';
      outTime.textContent = elapsed.toFixed(2) + ' ms';
      setStatus('❌ ' + err.message, 'error');
      console.error('[argon2id] error:', err);
    } finally {
      setLoading(false);
    }
  }

  /* ── Event listeners ──────────────────────────────────────────────── */

  btn.addEventListener('click', computeHash);

  // Allow Enter key in any input field to trigger hashing
  [fPass, fSalt, fTime, fMem, fPar, fLen].forEach((el) => {
    el.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') computeHash();
    });
  });
})();
