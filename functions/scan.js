// functions/scan.js
// Cloudflare Pages Function — jalan di edge (Workers runtime), bukan di browser.
// Endpoint: POST /scan
// Body JSON: { mode: "url", url: "https://xxx.pages.dev" }
//         atau { mode: "html", html: "<html>...</html>" }

// ------------------------------------------------------------------
// 0. REBRANDING (opsional) — ganti nama brand, title, deskripsi, logo, icon, gambar lain
// ------------------------------------------------------------------
function applyRebrand(html, rebrand) {
  if (!rebrand) return html;
  let out = html;

  // Title
  if (rebrand.title && rebrand.title.trim()) {
    const newTitle = rebrand.title.trim();
    if (/<title[^>]*>[\s\S]*?<\/title>/i.test(out)) {
      out = out.replace(/<title[^>]*>[\s\S]*?<\/title>/i, `<title>${escapeForHtmlText(newTitle)}</title>`);
    } else if (/<head[^>]*>/i.test(out)) {
      out = out.replace(/<head([^>]*)>/i, `<head$1>\n<title>${escapeForHtmlText(newTitle)}</title>`);
    }
  }

  // Meta description (+ og:description, twitter:description best-effort)
  if (rebrand.description && rebrand.description.trim()) {
    const desc = rebrand.description.trim().replace(/"/g, '&quot;');
    out = replaceOrInsertMeta(out, /<meta\s+name=["']description["'][^>]*>/i,
      `<meta name="description" content="${desc}">`);
    out = replaceOrInsertMeta(out, /<meta\s+property=["']og:description["'][^>]*>/i,
      `<meta property="og:description" content="${desc}">`, false);
    out = replaceOrInsertMeta(out, /<meta\s+name=["']twitter:description["'][^>]*>/i,
      `<meta name="twitter:description" content="${desc}">`, false);
  }

  // Nama brand: ganti semua kemunculan teks (case-insensitive)
  if (rebrand.brandOld && rebrand.brandOld.trim() && rebrand.brandNew !== undefined) {
    const escaped = rebrand.brandOld.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    out = out.replace(new RegExp(escaped, 'gi'), rebrand.brandNew);
  }

  // Logo: ganti semua kemunculan URL/path logo lama dengan yang baru
  if (rebrand.logoOld && rebrand.logoOld.trim() && rebrand.logoNew && rebrand.logoNew.trim()) {
    const escaped = rebrand.logoOld.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    out = out.replace(new RegExp(escaped, 'g'), rebrand.logoNew.trim());
  }

  // Icon / favicon baru — ganti semua <link rel="icon|shortcut icon|apple-touch-icon" href="...">
  if (rebrand.iconNew && rebrand.iconNew.trim()) {
    const iconUrl = rebrand.iconNew.trim();
    const iconTagRe = /<link\s+[^>]*rel=["'](?:shortcut icon|icon|apple-touch-icon)["'][^>]*>/gi;
    if (iconTagRe.test(out)) {
      out = out.replace(iconTagRe, (tag) => tag.replace(/href=["'][^"']*["']/i, `href="${iconUrl}"`));
    } else if (/<head[^>]*>/i.test(out)) {
      out = out.replace(/<head([^>]*)>/i, `<head$1>\n<link rel="icon" href="${iconUrl}">`);
    }
  }

  // Daftar penggantian link lain (login, CTA, sosial media, gambar, dll): [{old, new}, ...]
  if (Array.isArray(rebrand.linkReplacements)) {
    rebrand.linkReplacements.forEach(({ old: oldUrl, new: newUrl }) => {
      if (!oldUrl || !oldUrl.trim() || newUrl === undefined) return;
      const escaped = oldUrl.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      out = out.replace(new RegExp(escaped, 'g'), newUrl.trim());
    });
  }

  return out;
}

function escapeForHtmlText(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function replaceOrInsertMeta(html, findRe, newTag, insertIfMissing = true) {
  if (findRe.test(html)) {
    return html.replace(findRe, newTag);
  }
  if (insertIfMissing && /<head[^>]*>/i.test(html)) {
    return html.replace(/<head([^>]*)>/i, `<head$1>\n${newTag}`);
  }
  return html;
}

// ------------------------------------------------------------------
// 1. ATURAN DETEKSI
// ------------------------------------------------------------------
// scope: 'html'  -> dicek di konten HTML (termasuk isi <script> inline)
// scope: 'js'    -> juga dicek di file .js eksternal yang ikut di-fetch
// scope: 'both'  -> dicek di keduanya
const RULES = [
  { id: 'eval', level: 'danger', scope: 'both', label: 'Penggunaan eval()',
    re: /\beval\s*\(/i,
    desc: 'eval() menjalankan string sebagai kode — sering dipakai menyembunyikan payload.' },
  { id: 'function_ctor', level: 'danger', scope: 'both', label: 'new Function() dinamis',
    re: /new\s+Function\s*\(/i,
    desc: 'Membuat fungsi dari string, mirip eval(), umum untuk obfuscation.' },
  { id: 'document_write', level: 'warn', scope: 'both', label: 'document.write() dinamis',
    re: /document\.write\s*\(/i,
    desc: 'Sering dipakai menyuntikkan iklan/script pihak ketiga secara dinamis.' },
  { id: 'atob', level: 'warn', scope: 'both', label: 'Decoding Base64 (atob)',
    re: /\batob\s*\(/i,
    desc: 'Decode base64 saat runtime — bisa legit, tapi umum dipakai menyembunyikan payload.' },
  { id: 'fromcharcode', level: 'danger', scope: 'both', label: 'String.fromCharCode berlebihan',
    re: /String\.fromCharCode\s*\((?:[^)]*,){6,}/i,
    desc: 'Membangun string karakter demi karakter, pola khas kode ter-obfuscate.' },
  { id: 'unescape', level: 'warn', scope: 'both', label: 'unescape() tersembunyi',
    re: /\bunescape\s*\(/i,
    desc: 'Dipakai untuk decode payload yang di-encode.' },
  { id: 'js_uri_handler', level: 'danger', scope: 'html', label: 'Event handler javascript: URI',
    re: /on\w+\s*=\s*(["'])\s*javascript:[^"']*\1/i,
    desc: 'Inline event handler yang menjalankan javascript: URI langsung.' },
  { id: 'hidden_iframe', level: 'danger', scope: 'html', label: 'Iframe tersembunyi',
    re: /<iframe[^>]*(width=["']?0["']?|height=["']?0["']?|style=["'][^"']*display\s*:\s*none|opacity\s*:\s*0)[^>]*>/i,
    desc: 'Iframe 0px / display:none / opacity:0 — sering untuk clickjacking atau konten tersembunyi.' },
  { id: 'miner_keyword', level: 'danger', scope: 'both', label: 'Indikasi cryptominer',
    re: /(coinhive|cryptonight|crypto-?loot|webminepool|coin-?hive|minero\.cc|jsecoin)/i,
    desc: 'Kata kunci terkait skrip cryptomining ilegal di browser pengunjung.' },
  { id: 'shorturl_script', level: 'warn', scope: 'html', label: 'Script dari shortlink/redirector',
    re: /<script[^>]+src=["'][^"']*(bit\.ly|tinyurl|is\.gd|t\.co\/[a-z0-9]+)[^"']*["']/i,
    desc: 'Script dimuat dari layanan pemendek URL, sulit diverifikasi tujuannya.' },
  { id: 'http_script', level: 'warn', scope: 'html', label: 'Script eksternal via HTTP',
    re: /<script[^>]+src=["']http:\/\/[^"']+["']/i,
    desc: 'Dimuat lewat koneksi tidak terenkripsi, rawan man-in-the-middle.' },
  { id: 'obfuscated_blob', level: 'warn', scope: 'both', label: 'String terenkode panjang',
    re: /["'][A-Za-z0-9+\/=]{300,}["']/,
    desc: 'String panjang mirip base64/hex, indikasi payload tersembunyi.' },
  { id: 'debugger_trap', level: 'warn', scope: 'both', label: 'Anti-debugging (debugger)',
    re: /\bdebugger\s*;/,
    desc: 'Statement debugger dipakai sejumlah malware untuk mempersulit analisis.' },
  { id: 'auto_redirect', level: 'danger', scope: 'both', label: 'Auto popup/redirect via delay',
    re: /setTimeout\s*\(\s*function\s*\(\s*\)\s*\{\s*window\.(open|location)/i,
    desc: 'Popup/redirect otomatis setelah delay, pola umum malvertising.' },
  { id: 'hidden_form', level: 'warn', scope: 'html', label: 'Form tersembunyi mengirim data ke luar',
    re: /<form[^>]*style=["'][^"']*display\s*:\s*none[^"']*["'][^>]*action=["']https?:\/\//i,
    desc: 'Form tersembunyi yang mengirim data ke domain eksternal — indikasi pencurian data.' },
];

const MAX_EXTERNAL_SCRIPTS = 12;
const MAX_FETCH_BYTES = 2_000_000; // 2MB guard per resource

function escapeSample(s) {
  return s.length > 200 ? s.slice(0, 200) + '…' : s;
}

// Analisis + bersihkan konten HTML utama.
// autoRemove=false (default): semua temuan hanya dilaporkan, TIDAK ada yang dihapus —
// supaya script legit yang kebetulan match pola (tracking pixel, chat widget, dll) gak ikut rusak.
// autoRemove=true: baru script/iframe dengan level 'danger' dihapus.
function scanAndCleanHtml(html, autoRemove) {
  const findings = [];

  let cleaned = html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, (block) => {
    const hits = RULES.filter(r => (r.scope === 'html' || r.scope === 'both') && r.re.test(block));
    if (hits.length === 0) return block;
    const hasDanger = hits.some(h => h.level === 'danger');
    const willRemove = autoRemove && hasDanger;
    hits.forEach(h => {
      const m = block.match(h.re);
      findings.push({
        level: h.level, label: h.label, desc: h.desc,
        sample: escapeSample(m ? m[0] : ''), context: 'inline <script>', removed: willRemove,
      });
    });
    return willRemove ? '<!-- [DIHAPUS oleh Script Cleaner: script berbahaya terdeteksi] -->' : block;
  });

  const hiddenIframeRule = RULES.find(r => r.id === 'hidden_iframe');
  cleaned = cleaned.replace(/<iframe\b[^>]*>[\s\S]*?<\/iframe>|<iframe\b[^>]*\/?>/gi, (block) => {
    if (hiddenIframeRule.re.test(block)) {
      const willRemove = autoRemove;
      findings.push({
        level: 'danger', label: hiddenIframeRule.label, desc: hiddenIframeRule.desc,
        sample: escapeSample(block), context: '<iframe>', removed: willRemove,
      });
      return willRemove ? '<!-- [DIHAPUS oleh Script Cleaner: iframe tersembunyi terdeteksi] -->' : block;
    }
    return block;
  });

  const hiddenFormRule = RULES.find(r => r.id === 'hidden_form');
  const formMatches = html.match(new RegExp(hiddenFormRule.re.source, 'gi')) || [];
  formMatches.forEach(m => findings.push({
    level: 'warn', label: hiddenFormRule.label, desc: hiddenFormRule.desc,
    sample: escapeSample(m), context: '<form>', removed: false,
  }));

  const jsUriRule = RULES.find(r => r.id === 'js_uri_handler');
  const jsUriMatches = html.match(new RegExp(jsUriRule.re.source, 'gi')) || [];
  jsUriMatches.forEach(m => findings.push({
    level: 'danger', label: jsUriRule.label, desc: jsUriRule.desc,
    sample: escapeSample(m), context: 'atribut tag', removed: autoRemove,
  }));
  if (autoRemove) {
    cleaned = cleaned.replace(new RegExp(jsUriRule.re.source, 'gi'), 'onclick="/* dihapus: javascript: URI mencurigakan */"');
  }

  // Aturan http_script / shorturl_script cukup dilaporkan (tag <script src> tetap dibiarkan
  // karena file eksternalnya sendiri akan dianalisis terpisah).
  ['http_script', 'shorturl_script'].forEach(id => {
    const rule = RULES.find(r => r.id === id);
    const matches = html.match(new RegExp(rule.re.source, 'gi')) || [];
    matches.forEach(m => findings.push({
      level: rule.level, label: rule.label, desc: rule.desc,
      sample: escapeSample(m), context: '<script src>', removed: false,
    }));
  });

  return { cleaned, findings };
}

// Analisis file .js eksternal (tanpa modifikasi — kita tidak punya akses ubah file remote)
function scanJsContent(jsText) {
  const findings = [];
  RULES.filter(r => r.scope === 'js' || r.scope === 'both').forEach(rule => {
    const m = jsText.match(rule.re);
    if (m) {
      findings.push({
        level: rule.level, label: rule.label, desc: rule.desc,
        sample: escapeSample(m[0]), removed: false,
      });
    }
  });
  return findings;
}

function extractScriptSrcs(html, baseUrl) {
  const srcs = [];
  const re = /<script[^>]+src=["']([^"']+)["']/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    try {
      const abs = new URL(m[1], baseUrl).href;
      srcs.push(abs);
    } catch (e) { /* abaikan URL tidak valid */ }
  }
  return srcs;
}

async function fetchText(url, timeoutMs = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': 'ScriptCleanerBot/1.0 (+security-scan)' },
    });
    if (!res.ok) return { ok: false, status: res.status, text: '' };
    const reader = res.body ? res.body.getReader() : null;
    if (!reader) {
      const text = await res.text();
      return { ok: true, status: res.status, text: text.slice(0, MAX_FETCH_BYTES) };
    }
    let received = 0;
    let chunks = [];
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.length;
      chunks.push(value);
      if (received > MAX_FETCH_BYTES) break;
    }
    const buf = new Uint8Array(received);
    let offset = 0;
    for (const c of chunks) { buf.set(c, offset); offset += c.length; }
    const text = new TextDecoder('utf-8').decode(buf);
    return { ok: true, status: res.status, text };
  } catch (e) {
    return { ok: false, status: 0, text: '', error: String(e) };
  } finally {
    clearTimeout(timer);
  }
}

export async function onRequestPost(context) {
  const { request } = context;
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json({ error: 'Body harus JSON valid.' }, 400);
  }

  const mode = body.mode === 'url' ? 'url' : 'html';
  let mainHtml = '';
  let baseUrl = '';

  if (mode === 'url') {
    let targetUrl = (body.url || '').trim();
    if (!targetUrl) return json({ error: 'URL kosong.' }, 400);
    if (!/^https?:\/\//i.test(targetUrl)) targetUrl = 'https://' + targetUrl;

    let parsed;
    try { parsed = new URL(targetUrl); } catch (e) {
      return json({ error: 'URL tidak valid.' }, 400);
    }

    const fetched = await fetchText(parsed.href);
    if (!fetched.ok) {
      return json({ error: `Gagal mengambil URL (status ${fetched.status || 'timeout/koneksi gagal'}).` }, 502);
    }
    mainHtml = fetched.text;
    baseUrl = parsed.href;
  } else {
    mainHtml = body.html || '';
    if (!mainHtml.trim()) return json({ error: 'Kode HTML kosong.' }, 400);
  }

  const autoRemove = body.autoRemove === true;
  const rebrandedHtml = applyRebrand(mainHtml, body.rebrand);
  const { cleaned, findings } = scanAndCleanHtml(rebrandedHtml, autoRemove);

  // Ambil & scan file .js eksternal (khusus mode URL, karena butuh base URL absolut)
  const externalResults = [];
  if (mode === 'url') {
    const srcs = extractScriptSrcs(mainHtml, baseUrl).slice(0, MAX_EXTERNAL_SCRIPTS);
    for (const src of srcs) {
      const fetched = await fetchText(src, 6000);
      if (!fetched.ok) {
        externalResults.push({ url: src, ok: false, findings: [] });
        continue;
      }
      const jsFindings = scanJsContent(fetched.text);
      externalResults.push({ url: src, ok: true, findings: jsFindings });
    }
  }

  const dangerCount = findings.filter(f => f.level === 'danger').length
    + externalResults.reduce((n, r) => n + r.findings.filter(f => f.level === 'danger').length, 0);
  const warnCount = findings.filter(f => f.level === 'warn').length
    + externalResults.reduce((n, r) => n + r.findings.filter(f => f.level === 'warn').length, 0);
  const removedCount = findings.filter(f => f.removed).length;

  return json({
    mode,
    baseUrl: baseUrl || null,
    autoRemove,
    cleaned,
    findings,
    externalResults,
    summary: { dangerCount, warnCount, removedCount, scannedExternal: externalResults.length },
  });
}

export async function onRequestGet() {
  return json({ ok: true, message: 'Kirim POST ke endpoint ini dengan { mode: "url"|"html", url, html }.' });
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}
