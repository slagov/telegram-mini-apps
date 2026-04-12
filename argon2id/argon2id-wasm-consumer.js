/**
 * argon2id-wasm-consumer.js
 *
 * Two independent features:
 *
 *  1. COMPUTE — read parameters from the form, call argon2-browser WASM,
 *     display hex hash + PHC string + elapsed time.
 *
 *  2. PARSE — decode a PHC-encoded Argon2id string and show every parameter,
 *     including hashLen derived from the base64url hash segment.
 *
 * No external dependencies beyond window.argon2 (loaded from CDN).
 */

(function () {
  'use strict';

  /* ── DOM refs ─────────────────────────────────────────────────────── */
  const $ = (id) => document.getElementById(id);

  // Section 1 – compute
  const fPass    = $('f-pass');
  const fSalt    = $('f-salt');
  const fTime    = $('f-time');
  const fMem     = $('f-mem');
  const fPar     = $('f-par');
  const fLen     = $('f-len');
  const hashBtn  = $('hash-btn');
  const outHex   = $('out-hex');
  const outEnc   = $('out-encoded');
  const outTime  = $('out-time');
  const statusEl = $('status');

  // Section 2 – parse
  const fPhc       = $('f-phc');
  const parseBtn   = $('parse-btn');
  const parseResult = $('parse-result');

  /* ════════════════════════════════════════════════════════════════════
     SECTION 1 — COMPUTE
  ═══════════════════════════════════════════════════════════════════ */

  function setStatus(html, type) {
    statusEl.innerHTML = html;
    statusEl.className = 'status ' + type;
  }

  function setLoading(on) {
    hashBtn.disabled    = on;
    hashBtn.textContent = on ? 'Computing…' : '⚡ Compute Hash';
  }

  /**
   * Read and validate all form fields.
   * @returns {{ pass, salt, time, mem, parallelism, hashLen }}
   * @throws {Error} with a human-readable message on invalid input
   */
  function readParams() {
    const pass = fPass.value;
    if (!pass) throw new Error('Value to hash must not be empty.');

    const saltStr = fSalt.value;
    if (saltStr.length < 8)
      throw new Error('Salt must be at least 8 characters.');
    // Encode UTF-8 string → Uint8Array
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

    return { pass, salt, saltStr, time, mem, parallelism, hashLen };
  }

  async function computeHash() {
    if (typeof argon2 === 'undefined') {
      setStatus('❌ <b>argon2</b> global not found — CDN script failed to load.', 'error');
      return;
    }

    let params;
    try {
      params = readParams();
    } catch (e) {
      setStatus('⚠️ ' + e.message, 'error');
      return;
    }

    setLoading(true);
    setStatus('<span class="spinner"></span>Computing Argon2id hash…', 'loading');
    outHex.textContent  = '…';
    outEnc.textContent  = '…';
    outTime.textContent = '…';

    // Yield so the browser can repaint before the heavy WASM work starts.
    await new Promise((r) => setTimeout(r, 0));

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
        // version is always 19 (0x13) — the library does not expose it as a param
      });

      const elapsed = performance.now() - t0;

      outHex.textContent  = result.hashHex;
      outEnc.textContent  = result.encoded;
      outTime.textContent = elapsed.toFixed(2) + ' ms';

      setStatus('✅ Hash computed successfully via WASM!', 'success');

      // Offer the PHC string to the parser section for convenience
      fPhc.value = result.encoded;

      console.group('[argon2id] result');
      console.log('input      :', params.pass);
      console.log('salt (str) :', params.saltStr);
      console.log('t / m / p  :', params.time, '/', params.mem, '/', params.parallelism);
      console.log('hashLen    :', params.hashLen);
      console.log('version    : 19 (0x13) — fixed by RFC 9106');
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

  hashBtn.addEventListener('click', computeHash);
  [fPass, fSalt, fTime, fMem, fPar, fLen].forEach((el) =>
    el.addEventListener('keydown', (e) => { if (e.key === 'Enter') computeHash(); })
  );

  /* ════════════════════════════════════════════════════════════════════
     SECTION 2 — PARSE PHC STRING
  ═══════════════════════════════════════════════════════════════════

  PHC format for Argon2id:
    $argon2id$v=19$m=<KiB>,t=<iter>,p=<par>$<base64url-salt>$<base64url-hash>

  Segments (split by '$', first element is empty string):
    [0] ""
    [1] "argon2id"
    [2] "v=19"
    [3] "m=65536,t=2,p=1"
    [4] <base64url salt>
    [5] <base64url hash>

  hashLen in bytes = floor(base64url_length * 3 / 4)
  (base64url without padding: every 4 chars encode 3 bytes;
   for lengths not divisible by 4 the formula still holds because
   argon2-browser never emits padding characters)
  ═══════════════════════════════════════════════════════════════════ */

  /**
   * Decode a base64url-without-padding string to a Uint8Array.
   * Adds '=' padding as needed before calling atob().
   */
  function base64urlDecode(b64url) {
    // base64url → base64 standard
    let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    // Add padding
    while (b64.length % 4 !== 0) b64 += '=';
    const binary = atob(b64);
    const bytes  = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  /** Convert Uint8Array to lowercase hex string. */
  function toHex(bytes) {
    return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Parse a PHC-encoded Argon2id string.
   * @param {string} phc
   * @returns {object} parsed fields
   * @throws {Error} on malformed input
   */
  function parsePhc(phc) {
    const parts = phc.split('$');
    // parts: ['', 'argon2id', 'v=19', 'm=65536,t=2,p=1', '<salt_b64>', '<hash_b64>']
    if (parts.length < 6) throw new Error('Too few segments — expected 6 (split by $).');
    if (parts[0] !== '')  throw new Error('PHC string must start with $.');

    const algo = parts[1];
    if (!algo.startsWith('argon2')) throw new Error(`Unknown algorithm: "${algo}".`);

    // Version segment (may be absent in very old hashes)
    let versionStr = '?';
    let paramStr, saltB64, hashB64;

    if (parts[2].startsWith('v=')) {
      versionStr = parts[2];          // "v=19"
      paramStr   = parts[3];          // "m=65536,t=2,p=1"
      saltB64    = parts[4];
      hashB64    = parts[5];
    } else {
      // No version segment (legacy v=16 hashes omit it)
      versionStr = 'not present (legacy v=16)';
      paramStr   = parts[2];
      saltB64    = parts[3];
      hashB64    = parts[4];
    }

    // Parse param segment
    const paramMap = {};
    paramStr.split(',').forEach((kv) => {
      const [k, v] = kv.split('=');
      paramMap[k.trim()] = v ? v.trim() : '';
    });

    const m = parseInt(paramMap['m'], 10);
    const t = parseInt(paramMap['t'], 10);
    const p = parseInt(paramMap['p'], 10);

    // Decode salt
    let saltBytes, saltUtf8, saltHex;
    try {
      saltBytes = base64urlDecode(saltB64);
      saltHex   = toHex(saltBytes);
      saltUtf8  = new TextDecoder('utf-8', { fatal: false }).decode(saltBytes);
    } catch (_) {
      saltBytes = null;
      saltHex   = '(decode error)';
      saltUtf8  = '(decode error)';
    }

    // Decode hash
    let hashBytes, hashHex;
    try {
      hashBytes = base64urlDecode(hashB64);
      hashHex   = toHex(hashBytes);
    } catch (_) {
      hashBytes = null;
      hashHex   = '(decode error)';
    }

    // hashLen: derived from base64url string length (no padding chars)
    // Each base64 char encodes 6 bits; 4 chars = 3 bytes.
    // Without padding: floor(L * 6 / 8) = floor(L * 3 / 4)
    const hashLen = hashBytes ? hashBytes.length : Math.floor(hashB64.length * 3 / 4);

    return {
      algorithm:  algo,
      version:    versionStr,
      t, m, p,
      saltB64,
      saltHex,
      saltUtf8,
      saltLenBytes: saltBytes ? saltBytes.length : '?',
      hashB64,
      hashHex,
      hashLen,
    };
  }

  function renderParseResult(r) {
    const rows = [
      ['Algorithm',          r.algorithm],
      ['Version',            r.version],
      ['t (iterations)',     r.t],
      ['m (memory KiB)',     `${r.m} KiB = ${(r.m / 1024).toFixed(0)} MiB`],
      ['p (parallelism)',    r.p],
      ['hashLen (bytes)',    `${r.hashLen} bytes = ${r.hashLen * 8} bits  ← derived from base64url hash length`],
      ['Salt (base64url)',   r.saltB64],
      ['Salt (hex)',         r.saltHex],
      ['Salt (UTF-8 try)',   r.saltUtf8],
      ['Salt length',        `${r.saltLenBytes} bytes`],
      ['Hash (base64url)',   r.hashB64],
      ['Hash (hex)',         r.hashHex],
    ];

    const trs = rows.map(([label, val]) =>
      `<tr><td>${label}</td><td>${String(val)}</td></tr>`
    ).join('');

    parseResult.innerHTML = `<table class="parse-table">${trs}</table>`;
    parseResult.style.display = 'block';
  }

  function onParse() {
    const raw = fPhc.value.trim();
    if (!raw) {
      parseResult.innerHTML = '<span style="color:#eb5757">⚠️ Paste a PHC string first.</span>';
      parseResult.style.display = 'block';
      return;
    }
    try {
      const parsed = parsePhc(raw);
      renderParseResult(parsed);
      console.group('[argon2id] PHC parse');
      console.table(parsed);
      console.groupEnd();
    } catch (err) {
      parseResult.innerHTML = `<span style="color:#eb5757">❌ ${err.message}</span>`;
      parseResult.style.display = 'block';
      console.error('[argon2id] parse error:', err);
    }
  }

  parseBtn.addEventListener('click', onParse);
  fPhc.addEventListener('keydown', (e) => { if (e.key === 'Enter' && e.ctrlKey) onParse(); });

})();
