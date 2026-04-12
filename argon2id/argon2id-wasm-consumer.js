/**
 * argon2id-wasm-consumer.js
 *
 * Two independent features:
 *  1. COMPUTE — read parameters from the form, call argon2-browser WASM,
 *     display hex hash + PHC string + elapsed time.
 *  2. PARSE   — decode a PHC-encoded Argon2id string and show every parameter,
 *     including hashLen derived from the base64url hash segment.
 */

document.addEventListener('DOMContentLoaded', function () {
  'use strict';

  /* ── Safe DOM lookup (throws with a clear message if ID is missing) ── */
  function getEl(id) {
    var el = document.getElementById(id);
    if (!el) throw new Error('Element #' + id + ' not found in DOM.');
    return el;
  }

  var fPass, fSalt, fTime, fMem, fPar, fLen;
  var hashBtn, outHex, outEnc, outTime, statusEl;
  var fPhc, parseBtn, parseResult;

  try {
    fPass       = getEl('f-pass');
    fSalt       = getEl('f-salt');
    fTime       = getEl('f-time');
    fMem        = getEl('f-mem');
    fPar        = getEl('f-par');
    fLen        = getEl('f-len');
    hashBtn     = getEl('hash-btn');
    outHex      = getEl('out-hex');
    outEnc      = getEl('out-encoded');
    outTime     = getEl('out-time');
    statusEl    = getEl('status');
    fPhc        = getEl('f-phc');
    parseBtn    = getEl('parse-btn');
    parseResult = getEl('parse-result');
  } catch (initErr) {
    console.error('[argon2id-wasm-consumer] Init failed:', initErr.message);
    document.body.insertAdjacentHTML(
      'afterbegin',
      '<div style="background:#3a1a1a;color:#eb5757;padding:1rem;font-family:monospace">' +
        '❌ Script init error: ' + initErr.message + '</div>'
    );
    return;
  }

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

  function readParams() {
    var pass = fPass.value;
    if (!pass) throw new Error('Value to hash must not be empty.');

    var saltStr = fSalt.value;
    if (saltStr.length < 8) throw new Error('Salt must be at least 8 characters.');
    var salt = new TextEncoder().encode(saltStr);

    var time = parseInt(fTime.value, 10);
    if (!Number.isFinite(time) || time < 1 || time > 100)
      throw new Error('Iterations (t) must be between 1 and 100.');

    var mem = parseInt(fMem.value, 10);
    if (!Number.isFinite(mem) || mem < 1024)
      throw new Error('Memory (m) must be at least 1024 KiB.');

    var parallelism = parseInt(fPar.value, 10);
    if (!Number.isFinite(parallelism) || parallelism < 1 || parallelism > 16)
      throw new Error('Parallelism (p) must be between 1 and 16.');

    var hashLen = parseInt(fLen.value, 10);
    if (!Number.isFinite(hashLen) || hashLen < 4 || hashLen > 64)
      throw new Error('Hash length must be between 4 and 64 bytes.');

    return { pass: pass, salt: salt, saltStr: saltStr,
             time: time, mem: mem, parallelism: parallelism, hashLen: hashLen };
  }

  async function computeHash() {
    if (typeof argon2 === 'undefined') {
      setStatus('❌ <b>argon2</b> global not found — CDN script failed to load.', 'error');
      return;
    }

    var params;
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

    await new Promise(function (r) { setTimeout(r, 0); });

    var t0 = performance.now();
    try {
      var result = await argon2.hash({
        pass:        params.pass,
        salt:        params.salt,
        time:        params.time,
        mem:         params.mem,
        parallelism: params.parallelism,
        hashLen:     params.hashLen,
        type:        argon2.ArgonType.Argon2id,
      });

      var elapsed = performance.now() - t0;

      outHex.textContent  = result.hashHex;
      outEnc.textContent  = result.encoded;
      outTime.textContent = elapsed.toFixed(2) + ' ms';

      setStatus('✅ Hash computed successfully via WASM!', 'success');

      // Auto-fill the PHC parser textarea
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
      var elapsed2 = performance.now() - t0;
      outHex.textContent  = 'Error';
      outEnc.textContent  = 'Error';
      outTime.textContent = elapsed2.toFixed(2) + ' ms';
      setStatus('❌ ' + err.message, 'error');
      console.error('[argon2id] error:', err);
    } finally {
      setLoading(false);
    }
  }

  hashBtn.addEventListener('click', computeHash);
  [fPass, fSalt, fTime, fMem, fPar, fLen].forEach(function (el) {
    el.addEventListener('keydown', function (e) { if (e.key === 'Enter') computeHash(); });
  });

  /* ════════════════════════════════════════════════════════════════════
     SECTION 2 — PARSE PHC STRING
  ═══════════════════════════════════════════════════════════════════

  PHC format:
    $argon2id$v=19$m=<KiB>,t=<iter>,p=<par>$<base64url-salt>$<base64url-hash>

  Split by '$':
    [0] ""          (before first $)
    [1] "argon2id"
    [2] "v=19"
    [3] "m=65536,t=2,p=1"
    [4] <base64url salt>
    [5] <base64url hash>

  hashLen (bytes) = floor(base64url_length × 3 / 4)
  ═══════════════════════════════════════════════════════════════════ */

  function base64urlDecode(b64url) {
    var b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4 !== 0) b64 += '=';
    var binary = atob(b64);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function toHex(bytes) {
    return Array.from(bytes).map(function (b) {
      return b.toString(16).padStart(2, '0');
    }).join('');
  }

  function parsePhc(phc) {
    var parts = phc.split('$');
    if (parts.length < 6) throw new Error('Too few segments — expected at least 6 parts when split by "$".');
    if (parts[0] !== '')  throw new Error('PHC string must start with "$".');

    var algo = parts[1];
    if (!algo.startsWith('argon2')) throw new Error('Unknown algorithm: "' + algo + '".');

    var versionStr, paramStr, saltB64, hashB64;

    if (parts[2].startsWith('v=')) {
      versionStr = parts[2];   // "v=19"
      paramStr   = parts[3];   // "m=65536,t=2,p=1"
      saltB64    = parts[4];
      hashB64    = parts[5];
    } else {
      versionStr = 'not present (legacy v=16)';
      paramStr   = parts[2];
      saltB64    = parts[3];
      hashB64    = parts[4];
    }

    var paramMap = {};
    paramStr.split(',').forEach(function (kv) {
      var pair = kv.split('=');
      paramMap[pair[0].trim()] = pair[1] ? pair[1].trim() : '';
    });

    var m = parseInt(paramMap['m'], 10);
    var t = parseInt(paramMap['t'], 10);
    var p = parseInt(paramMap['p'], 10);

    var saltBytes, saltUtf8, saltHex;
    try {
      saltBytes = base64urlDecode(saltB64);
      saltHex   = toHex(saltBytes);
      saltUtf8  = new TextDecoder('utf-8', { fatal: false }).decode(saltBytes);
    } catch (_) {
      saltBytes = null;
      saltHex   = '(decode error)';
      saltUtf8  = '(decode error)';
    }

    var hashBytes, hashHex;
    try {
      hashBytes = base64urlDecode(hashB64);
      hashHex   = toHex(hashBytes);
    } catch (_) {
      hashBytes = null;
      hashHex   = '(decode error)';
    }

    var hashLen = hashBytes ? hashBytes.length : Math.floor(hashB64.length * 3 / 4);

    return {
      algorithm:    algo,
      version:      versionStr,
      t: t, m: m, p: p,
      saltB64:      saltB64,
      saltHex:      saltHex,
      saltUtf8:     saltUtf8,
      saltLenBytes: saltBytes ? saltBytes.length : '?',
      hashB64:      hashB64,
      hashHex:      hashHex,
      hashLen:      hashLen,
    };
  }

  function renderParseResult(r) {
    var rows = [
      ['Algorithm',        r.algorithm],
      ['Version',          r.version],
      ['t (iterations)',   r.t],
      ['m (memory KiB)',   r.m + ' KiB = ' + (r.m / 1024).toFixed(0) + ' MiB'],
      ['p (parallelism)',  r.p],
      ['hashLen',          r.hashLen + ' bytes = ' + (r.hashLen * 8) + ' bits  ← derived from base64url hash length'],
      ['Salt (base64url)', r.saltB64],
      ['Salt (hex)',       r.saltHex],
      ['Salt (UTF-8)',     r.saltUtf8],
      ['Salt length',      r.saltLenBytes + ' bytes'],
      ['Hash (base64url)', r.hashB64],
      ['Hash (hex)',       r.hashHex],
    ];

    var trs = rows.map(function (row) {
      return '<tr><td>' + row[0] + '</td><td>' + String(row[1]) + '</td></tr>';
    }).join('');

    parseResult.innerHTML = '<table class="parse-table">' + trs + '</table>';
    parseResult.style.display = 'block';
  }

  function onParse() {
    var raw = fPhc.value.trim();
    if (!raw) {
      parseResult.innerHTML = '<span style="color:#eb5757">⚠️ Paste a PHC string first.</span>';
      parseResult.style.display = 'block';
      return;
    }
    try {
      var parsed = parsePhc(raw);
      renderParseResult(parsed);
      console.group('[argon2id] PHC parse');
      console.table(parsed);
      console.groupEnd();
    } catch (err) {
      parseResult.innerHTML = '<span style="color:#eb5757">❌ ' + err.message + '</span>';
      parseResult.style.display = 'block';
      console.error('[argon2id] parse error:', err);
    }
  }

  parseBtn.addEventListener('click', onParse);
  fPhc.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && e.ctrlKey) onParse();
  });

  console.log('[argon2id-wasm-consumer] Initialised. Both sections ready.');
});
