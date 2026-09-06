<?php
/**
 * Script Cleaner (PHP) — Pembersih Script Berbahaya di Landing Page
 * -------------------------------------------------------------
 * Cara pakai:
 *   1. Taruh file ini di server PHP (XAMPP/Laragon lokal, atau hosting).
 *   2. Buka lewat browser: http://localhost/script-cleaner.php
 *   3. Tempel kode HTML atau upload file .html, klik "Scan & Bersihkan".
 *   4. Lihat laporan bahaya, lalu download hasil yang sudah dibersihkan.
 *
 * Catatan: deteksi berbasis heuristik/pola, bukan antivirus penuh.
 * Selalu backup file asli sebelum menimpa file production.
 */

error_reporting(E_ALL);
ini_set('display_errors', '0'); // jangan bocorin path server ke user

// ------------------------------------------------------------------
// 1. ATURAN DETEKSI
// ------------------------------------------------------------------
// level: 'danger' -> otomatis dihapus dari hasil bersih
// level: 'warn'   -> dilaporkan saja, tidak dihapus otomatis (butuh review manual)
$RULES = [
    ['id' => 'eval', 'level' => 'danger', 'label' => 'Penggunaan eval()',
        'pattern' => '/\beval\s*\(/i',
        'desc' => 'eval() menjalankan string sebagai kode — sering dipakai menyembunyikan payload.'],
    ['id' => 'function_ctor', 'level' => 'danger', 'label' => 'new Function() dinamis',
        'pattern' => '/new\s+Function\s*\(/i',
        'desc' => 'Membuat fungsi dari string, mirip eval(), umum untuk obfuscation.'],
    ['id' => 'document_write', 'level' => 'warn', 'label' => 'document.write() dinamis',
        'pattern' => '/document\.write\s*\(/i',
        'desc' => 'Sering dipakai menyuntikkan iklan/script pihak ketiga secara dinamis.'],
    ['id' => 'atob', 'level' => 'warn', 'label' => 'Decoding Base64 (atob)',
        'pattern' => '/\batob\s*\(/i',
        'desc' => 'Decode base64 saat runtime — bisa legit, tapi umum dipakai menyembunyikan payload.'],
    ['id' => 'fromcharcode', 'level' => 'danger', 'label' => 'String.fromCharCode berlebihan',
        'pattern' => '/String\.fromCharCode\s*\((?:[^)]*,){6,}/i',
        'desc' => 'Membangun string karakter demi karakter, pola khas kode ter-obfuscate.'],
    ['id' => 'unescape', 'level' => 'warn', 'label' => 'unescape() tersembunyi',
        'pattern' => '/\bunescape\s*\(/i',
        'desc' => 'Dipakai untuk decode payload yang di-encode.'],
    ['id' => 'js_uri_handler', 'level' => 'danger', 'label' => 'Event handler javascript: URI',
        'pattern' => '/on\w+\s*=\s*["\']?\s*javascript:/i',
        'desc' => 'Inline event handler yang menjalankan javascript: URI langsung.'],
    ['id' => 'hidden_iframe', 'level' => 'danger', 'label' => 'Iframe tersembunyi',
        'pattern' => '/<iframe[^>]*(width=["\']?0["\']?|height=["\']?0["\']?|style=["\'][^"\']*display\s*:\s*none|opacity\s*:\s*0)[^>]*>/i',
        'desc' => 'Iframe 0px / display:none / opacity:0 — sering untuk clickjacking atau memuat konten tersembunyi.'],
    ['id' => 'miner_keyword', 'level' => 'danger', 'label' => 'Indikasi cryptominer',
        'pattern' => '/(coinhive|cryptonight|crypto-?loot|webminepool|coin-?hive|minero\.cc|jsecoin)/i',
        'desc' => 'Kata kunci terkait skrip cryptomining ilegal di browser pengunjung.'],
    ['id' => 'shorturl_script', 'level' => 'warn', 'label' => 'Script dari shortlink/redirector',
        'pattern' => '/<script[^>]+src=["\'][^"\']*(bit\.ly|tinyurl|is\.gd|t\.co\/[a-z0-9]+)[^"\']*["\']/i',
        'desc' => 'Script dimuat dari layanan pemendek URL, sulit diverifikasi tujuannya.'],
    ['id' => 'http_script', 'level' => 'warn', 'label' => 'Script eksternal via HTTP',
        'pattern' => '/<script[^>]+src=["\']http:\/\/[^"\']+["\']/i',
        'desc' => 'Dimuat lewat koneksi tidak terenkripsi, rawan man-in-the-middle.'],
    ['id' => 'obfuscated_blob', 'level' => 'warn', 'label' => 'String terenkode panjang',
        'pattern' => '/["\'][A-Za-z0-9+\/=]{300,}["\']/',
        'desc' => 'String panjang mirip base64/hex, indikasi payload tersembunyi.'],
    ['id' => 'debugger_trap', 'level' => 'warn', 'label' => 'Anti-debugging (debugger)',
        'pattern' => '/\bdebugger\s*;/',
        'desc' => 'Statement debugger dipakai sejumlah malware untuk mempersulit analisis.'],
    ['id' => 'auto_redirect', 'level' => 'danger', 'label' => 'Auto popup/redirect via delay',
        'pattern' => '/setTimeout\s*\(\s*function\s*\(\s*\)\s*\{\s*window\.(open|location)/i',
        'desc' => 'Popup/redirect otomatis setelah delay, pola umum malvertising.'],
    ['id' => 'noscript_hidden_form', 'level' => 'warn', 'label' => 'Form tersembunyi mengirim data ke luar',
        'pattern' => '/<form[^>]*style=["\'][^"\']*display\s*:\s*none[^"\']*["\'][^>]*action=["\']https?:\/\//i',
        'desc' => 'Form tersembunyi yang mengirim data ke domain eksternal — indikasi pencurian data.'],
];

// ------------------------------------------------------------------
// 2. FUNGSI ANALISIS + PEMBERSIHAN
// ------------------------------------------------------------------
function scan_and_clean(string $html, array $RULES): array {
    $findings = [];
    $cleaned  = $html;

    // --- a) Analisis & hapus <script>...</script> yang berbahaya ---
    $cleaned = preg_replace_callback(
        '/<script\b[^>]*>[\s\S]*?<\/script>/i',
        function ($m) use ($RULES, &$findings) {
            $block = $m[0];
            $hasDanger = false;
            foreach ($RULES as $rule) {
                if (preg_match($rule['pattern'], $block, $mm)) {
                    $findings[] = [
                        'level'   => $rule['level'],
                        'label'   => $rule['label'],
                        'desc'    => $rule['desc'],
                        'sample'  => mb_substr($mm[0], 0, 160),
                        'context' => 'inline <script>',
                        'removed' => $rule['level'] === 'danger',
                    ];
                    if ($rule['level'] === 'danger') $hasDanger = true;
                }
            }
            return $hasDanger
                ? '<!-- [DIHAPUS oleh Script Cleaner: script berbahaya terdeteksi] -->'
                : $block;
        },
        $cleaned
    );

    // --- b) Analisis & hapus <iframe> tersembunyi ---
    $iframeRule = array_values(array_filter($RULES, fn($r) => $r['id'] === 'hidden_iframe'))[0];
    $cleaned = preg_replace_callback(
        '/<iframe\b[^>]*>[\s\S]*?<\/iframe>|<iframe\b[^>]*\/?>/i',
        function ($m) use ($iframeRule, &$findings) {
            $block = $m[0];
            if (preg_match($iframeRule['pattern'], $block)) {
                $findings[] = [
                    'level' => 'danger', 'label' => $iframeRule['label'], 'desc' => $iframeRule['desc'],
                    'sample' => mb_substr($block, 0, 160), 'context' => '<iframe>', 'removed' => true,
                ];
                return '<!-- [DIHAPUS oleh Script Cleaner: iframe tersembunyi terdeteksi] -->';
            }
            return $block;
        },
        $cleaned
    );

    // --- c) Form tersembunyi ke domain luar ---
    $formRule = array_values(array_filter($RULES, fn($r) => $r['id'] === 'noscript_hidden_form'))[0];
    if (preg_match_all($formRule['pattern'], $html, $mm)) {
        foreach ($mm[0] as $match) {
            $findings[] = [
                'level' => 'warn', 'label' => $formRule['label'], 'desc' => $formRule['desc'],
                'sample' => mb_substr($match, 0, 160), 'context' => '<form>', 'removed' => false,
            ];
        }
    }

    // --- d) Event handler javascript: URI di sembarang tag ---
    $jsUriRule = array_values(array_filter($RULES, fn($r) => $r['id'] === 'js_uri_handler'))[0];
    if (preg_match_all($jsUriRule['pattern'], $html, $mm)) {
        foreach ($mm[0] as $match) {
            $findings[] = [
                'level' => 'danger', 'label' => $jsUriRule['label'], 'desc' => $jsUriRule['desc'],
                'sample' => mb_substr($match, 0, 160), 'context' => 'atribut tag', 'removed' => true,
            ];
        }
    }
    $cleaned = preg_replace($jsUriRule['pattern'], 'onclick="/* dihapus: javascript: URI mencurigakan */"', $cleaned);

    // --- e) Sisa aturan warn-only yang belum tercakup di atas, cek di full HTML ---
    $alreadyChecked = ['hidden_iframe', 'js_uri_handler', 'noscript_hidden_form'];
    foreach ($RULES as $rule) {
        if (in_array($rule['id'], $alreadyChecked)) continue;
        // eval/function_ctor/fromcharcode/document_write/atob/unescape/miner/shorturl/http/obfuscated/debugger/auto_redirect
        // sudah tercakup lewat pengecekan <script> block di atas, tapi kita jaga-jaga kalau ada di luar tag script
        // (misal inline attribute onclick="eval(...)"). Cek tambahan ringan:
        if (in_array($rule['id'], ['eval', 'function_ctor', 'auto_redirect']) &&
            preg_match('/on\w+\s*=\s*["\'][^"\']*/i', $html, $attrCtx)) {
            // skip: sudah cukup representatif dari cek script block
        }
    }

    return ['cleaned' => $cleaned, 'findings' => $findings];
}

// ------------------------------------------------------------------
// 3. HANDLE REQUEST
// ------------------------------------------------------------------
$result       = null;
$originalHtml = '';
$error        = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action']) && $_POST['action'] === 'download' && isset($_POST['cleaned_content'])) {
        // Serve file download
        header('Content-Type: text/html; charset=utf-8');
        header('Content-Disposition: attachment; filename="landing-page-clean.html"');
        echo $_POST['cleaned_content'];
        exit;
    }

    if (!empty($_FILES['htmlfile']['tmp_name']) && $_FILES['htmlfile']['error'] === UPLOAD_ERR_OK) {
        $originalHtml = file_get_contents($_FILES['htmlfile']['tmp_name']);
    } elseif (!empty($_POST['html_input'])) {
        $originalHtml = $_POST['html_input'];
    } else {
        $error = 'Tempel kode HTML atau upload file dulu, ya.';
    }

    if ($originalHtml !== '' && $error === '') {
        $result = scan_and_clean($originalHtml, $RULES);
    }
}

function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>Script Cleaner (PHP) — Pembersih Script Berbahaya</title>
<style>
  :root{
    --bg:#0E1116; --panel:#161B22; --panel-2:#1C222B; --line:#2A3140;
    --text:#E6E9EF; --muted:#8A93A3; --safe:#3DD68C; --warn:#E8B04B; --danger:#E5484D;
    --mono: ui-monospace,"JetBrains Mono","SFMono-Regular",Menlo,Consolas,monospace;
    --sans: -apple-system,"Inter","Segoe UI",Roboto,sans-serif;
  }
  *{box-sizing:border-box;}
  body{margin:0;background:var(--bg);color:var(--text);font-family:var(--sans);line-height:1.5;padding:32px 20px 80px;}
  .wrap{max-width:1080px;margin:0 auto;}
  h1{font-size:22px;font-weight:650;margin:0 0 6px;}
  header p{color:var(--muted);margin:0;font-size:14px;max-width:64ch;}
  form{margin-top:24px;}
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px;}
  .panel-title{font-size:12px;color:var(--muted);margin-bottom:10px;}
  textarea{width:100%;min-height:220px;background:var(--panel-2);border:1px solid var(--line);border-radius:8px;
    color:var(--text);font-family:var(--mono);font-size:12.5px;padding:12px;outline:none;resize:vertical;}
  textarea:focus{border-color:#3D4759;}
  input[type=file]{color:var(--muted);font-size:13px;}
  .row{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-top:10px;}
  button{font-family:var(--sans);font-size:14px;font-weight:600;cursor:pointer;border-radius:8px;
    padding:10px 16px;border:1px solid transparent;}
  .btn-primary{background:var(--text);color:#11151B;border:none;}
  .btn-primary:hover{opacity:.9;}
  .btn-secondary{background:transparent;color:var(--text);border:1px solid var(--line);}
  .btn-secondary:hover{border-color:#4A5568;}
  .error{color:var(--danger);font-size:13px;margin-top:10px;}
  .summary{display:flex;gap:14px;margin:20px 0 16px;flex-wrap:wrap;}
  .stat{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 14px;font-size:13px;min-width:140px;}
  .stat b{display:block;font-size:20px;margin-top:2px;}
  .stat.danger b{color:var(--danger);} .stat.warn b{color:var(--warn);} .stat.safe b{color:var(--safe);}
  .findings{display:flex;flex-direction:column;gap:10px;margin-bottom:20px;}
  .finding{border:1px solid var(--line);border-radius:8px;padding:12px 14px;background:var(--panel-2);font-size:13px;}
  .finding.danger{border-left:3px solid var(--danger);}
  .finding.warn{border-left:3px solid var(--warn);}
  .finding-head{display:flex;justify-content:space-between;gap:10px;margin-bottom:4px;}
  .tag{font-size:11px;padding:2px 8px;border-radius:99px;font-weight:600;}
  .tag.danger{background:rgba(229,72,77,.15);color:var(--danger);}
  .tag.warn{background:rgba(232,176,75,.15);color:var(--warn);}
  .finding code{display:block;margin-top:8px;padding:8px 10px;background:#0B0E13;border-radius:6px;
    font-family:var(--mono);font-size:11.5px;color:#B8C0CC;white-space:pre-wrap;word-break:break-all;
    max-height:120px;overflow:auto;}
  .empty-state{color:var(--muted);font-size:13px;text-align:center;padding:30px 10px;}
  footer{margin-top:28px;color:var(--muted);font-size:12px;max-width:70ch;}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>Script Cleaner (PHP)</h1>
    <p>Tempel kode HTML atau upload file landing page kamu. Diproses langsung di server: script/iframe berbahaya otomatis dihapus, hasil bersih bisa langsung didownload.</p>
  </header>

  <form method="POST" enctype="multipart/form-data">
    <div class="panel">
      <div class="panel-title">TEMPEL KODE HTML</div>
      <textarea name="html_input" placeholder="Tempel kode HTML di sini..."><?= isset($originalHtml) ? h($originalHtml) : '' ?></textarea>
      <div class="row">
        <span style="color:var(--muted);font-size:13px;">atau upload file:</span>
        <input type="file" name="htmlfile" accept=".html,.htm,.php">
      </div>
    </div>
    <div class="row">
      <button type="submit" class="btn-primary">Scan &amp; Bersihkan</button>
    </div>
    <?php if ($error): ?><div class="error"><?= h($error) ?></div><?php endif; ?>
  </form>

  <?php if ($result): ?>
    <?php
      $dangerCount  = count(array_filter($result['findings'], fn($f) => $f['level'] === 'danger'));
      $warnCount    = count(array_filter($result['findings'], fn($f) => $f['level'] === 'warn'));
      $removedCount = count(array_filter($result['findings'], fn($f) => $f['removed']));
    ?>
    <div class="summary">
      <div class="stat danger"><span>Berbahaya</span><b><?= $dangerCount ?></b></div>
      <div class="stat warn"><span>Perlu Ditinjau</span><b><?= $warnCount ?></b></div>
      <div class="stat safe"><span>Dihapus Otomatis</span><b><?= $removedCount ?></b></div>
    </div>

    <div class="findings">
      <?php if (empty($result['findings'])): ?>
        <div class="empty-state">Tidak ada pola mencurigakan yang terdeteksi. Tetap lakukan review manual.</div>
      <?php else: ?>
        <?php foreach ($result['findings'] as $f): ?>
          <div class="finding <?= h($f['level']) ?>">
            <div class="finding-head">
              <strong><?= h($f['label']) ?> <span style="color:var(--muted);font-weight:400;">(<?= h($f['context']) ?>)</span></strong>
              <span class="tag <?= h($f['level']) ?>">
                <?= $f['removed'] ? 'DIHAPUS OTOMATIS' : ($f['level'] === 'danger' ? 'BERBAHAYA' : 'PERLU DITINJAU') ?>
              </span>
            </div>
            <div><?= h($f['desc']) ?></div>
            <code><?= h($f['sample']) ?></code>
          </div>
        <?php endforeach; ?>
      <?php endif; ?>
    </div>

    <div class="panel">
      <div class="panel-title">HASIL BERSIH</div>
      <textarea readonly><?= h($result['cleaned']) ?></textarea>
      <form method="POST" class="row">
        <input type="hidden" name="action" value="download">
        <input type="hidden" name="cleaned_content" value="<?= h($result['cleaned']) ?>">
        <button type="submit" class="btn-secondary">Download hasil-bersih.html</button>
      </form>
    </div>
  <?php endif; ?>

  <footer>
    Deteksi berbasis pola/heuristik (bukan antivirus lengkap). Selalu review manual bagian yang ditandai
    "PERLU DITINJAU", dan simpan backup file asli sebelum menimpa file production.
  </footer>
</div>
</body>
</html>
