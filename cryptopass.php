<?php
/**
 * CryptoPass – All-in-one web toolbox for hashing, encoding, and cryptography.
 * Single file app. Requires PHP 8.0+ with OpenSSL and Hash extensions enabled.
 * Design: light, clean, TailwindCSS (CDN).
 */

declare(strict_types=1);

ini_set('display_errors', '1');
error_reporting(E_ALL);

// ---------- helpers ----------
function post($key, $default = '') { return isset($_POST[$key]) ? trim((string)$_POST[$key]) : $default; }
function has_algo(string $algo): bool { return in_array(strtolower($algo), array_map('strtolower', hash_algos()), true); }
function safe_hex(string $s): string { return bin2hex($s); }
function from_hex(string $hex): string {
    $hex = preg_replace('/\s+/', '', $hex);
    if ($hex === '') return '';
    if (preg_match('/^[0-9a-fA-F]*$/', $hex) !== 1 || (strlen($hex) % 2) !== 0) {
        throw new RuntimeException('Invalid hex input');
    }
    return pack('H*', $hex);
}
function b64u_enc(string $s): string { return rtrim(strtr(base64_encode($s), '+/', '-_'), '='); }
function b64u_dec(string $s): string { return base64_decode(strtr($s . str_repeat('=', (4 - strlen($s) % 4) % 4), '-_', '+/')); }

// Base32 (RFC 4648)
function base32_encode_rfc(string $data): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    foreach (str_split($data) as $c) { $bits .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT); }
    $out = ''; for ($i = 0; $i < strlen($bits); $i += 5) {
        $chunk = substr($bits, $i, 5);
        if (strlen($chunk) < 5) $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
        $out .= $alphabet[bindec($chunk)];
    }
    while (strlen($out) % 8 !== 0) $out .= '=';
    return $out;
}
function base32_decode_rfc(string $data): string {
    $data = strtoupper(preg_replace('/\s+/', '', $data));
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $data = rtrim($data, '=');
    $bits = ''; $out = '';
    foreach (str_split($data) as $c) {
        $pos = strpos($alphabet, $c);
        if ($pos === false) throw new RuntimeException('Invalid Base32 character');
        $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
    }
    for ($i = 0; $i + 8 <= strlen($bits); $i += 8) {
        $out .= chr(bindec(substr($bits, $i, 8)));
    }
    return $out;
}

// Base58 (Bitcoin alphabet)
function base58_encode(string $data): string {
    $alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    if ($data === '') return '';
    $int = gmp_import($data, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    $encoded = '';
    while ($int > 0) {
        $r = gmp_intval(gmp_mod($int, 58));
        $encoded = $alphabet[$r] . $encoded;
        $int = gmp_div_q($int, 58);
    }
    // leading zeros
    foreach (str_split($data) as $c) { if ($c === "\x00") $encoded = '1' . $encoded; else break; }
    return $encoded;
}
function base58_decode(string $str): string {
    $alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    if ($str === '') return '';
    $int = gmp_init(0);
    foreach (str_split($str) as $c) {
        $pos = strpos($alphabet, $c);
        if ($pos === false) throw new RuntimeException('Invalid Base58 character');
        $int = gmp_add(gmp_mul($int, 58), $pos);
    }
    $bin = gmp_export($int, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    if ($bin === false) $bin = '';
    // leading ones -> leading zeros
    $leading = 0; foreach (str_split($str) as $c) { if ($c === '1') $leading++; else break; }
    return str_repeat("\x00", $leading) . $bin;
}

// Pretty JSON/XML
function pretty_json(string $s): string {
    $decoded = json_decode($s, true);
    if (json_last_error() !== JSON_ERROR_NONE) throw new RuntimeException('Invalid JSON: ' . json_last_error_msg());
    return json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
}
function minify_json(string $s): string {
    $decoded = json_decode($s, true);
    if (json_last_error() !== JSON_ERROR_NONE) throw new RuntimeException('Invalid JSON: ' . json_last_error_msg());
    return json_encode($decoded, JSON_UNESCAPED_SLASHES);
}
function pretty_xml(string $s): string {
    $dom = new DOMDocument('1.0');
    $dom->preserveWhiteSpace = false;
    if (!$dom->loadXML($s)) throw new RuntimeException('Invalid XML');
    $dom->formatOutput = true; return $dom->saveXML();
}
function minify_xml(string $s): string {
    $dom = new DOMDocument('1.0');
    $dom->preserveWhiteSpace = false;
    if (!$dom->loadXML($s)) throw new RuntimeException('Invalid XML');
    $dom->formatOutput = false; return $dom->saveXML();
}

// RSA & ECDSA
function rsa_generate(int $bits = 2048): array {
    $res = openssl_pkey_new(['private_key_bits' => $bits, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    openssl_pkey_export($res, $priv);
    $details = openssl_pkey_get_details($res);
    return ['private' => $priv, 'public' => $details['key']];
}
function rsa_encrypt(string $pubKey, string $msg): string {
    $ok = openssl_public_encrypt($msg, $out, $pubKey, OPENSSL_PKCS1_OAEP_PADDING);
    if (!$ok) throw new RuntimeException('RSA encrypt failed');
    return base64_encode($out);
}
function rsa_decrypt(string $privKeyB64, string $b64): string {
    $privKey = $privKeyB64;
    $cipher = base64_decode($b64, true);
    if ($cipher === false) throw new RuntimeException('Invalid Base64');
    $ok = openssl_private_decrypt($cipher, $out, $privKey, OPENSSL_PKCS1_OAEP_PADDING);
    if (!$ok) throw new RuntimeException('RSA decrypt failed');
    return $out;
}
function rsa_sign(string $privKey, string $msg, string $algo = 'sha256'): string {
    $sig = ''; $ok = openssl_sign($msg, $sig, $privKey, $algo);
    if (!$ok) throw new RuntimeException('RSA sign failed');
    return base64_encode($sig);
}
function rsa_verify(string $pubKey, string $msg, string $b64sig, string $algo = 'sha256'): bool {
    $sig = base64_decode($b64sig, true); if ($sig === false) return false;
    return openssl_verify($msg, $sig, $pubKey, $algo) === 1;
}
function ecdsa_generate(string $curve = 'prime256v1'): array {
    $res = openssl_pkey_new([
        'private_key_type' => OPENSSL_KEYTYPE_EC,
        'curve_name' => $curve,
    ]);
    openssl_pkey_export($res, $priv);
    $details = openssl_pkey_get_details($res);
    return ['private' => $priv, 'public' => $details['key']];
}
function ecdsa_sign(string $privKey, string $msg, string $algo = 'sha256'): string {
    $sig = ''; $ok = openssl_sign($msg, $sig, $privKey, $algo);
    if (!$ok) throw new RuntimeException('ECDSA sign failed');
    return base64_encode($sig);
}
function ecdsa_verify(string $pubKey, string $msg, string $b64sig, string $algo = 'sha256'): bool {
    $sig = base64_decode($b64sig, true); if ($sig === false) return false;
    return openssl_verify($msg, $sig, $pubKey, $algo) === 1;
}

// Symmetric ciphers (OpenSSL)
function cipher_encrypt(string $cipher, string $keyHex, string $ivHex, string $plaintext, bool $isGCM = false): string {
    $key = from_hex($keyHex); $iv = $ivHex !== '' ? from_hex($ivHex) : '';
    if ($isGCM) {
        $tag = '';
        $out = openssl_encrypt($plaintext, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        if ($out === false) throw new RuntimeException('Encrypt failed');
        return base64_encode($iv . $out . $tag);
    }
    $out = openssl_encrypt($plaintext, $cipher, $key, OPENSSL_RAW_DATA, $iv);
    if ($out === false) throw new RuntimeException('Encrypt failed');
    return base64_encode($iv . $out);
}
function cipher_decrypt(string $cipher, string $keyHex, string $payloadB64, bool $isGCM = false, int $ivLen = 16): string {
    $key = from_hex($keyHex);
    $payload = base64_decode($payloadB64, true);
    if ($payload === false) throw new RuntimeException('Invalid Base64 payload');
    if ($isGCM) {
        if (strlen($payload) < $ivLen + 16) throw new RuntimeException('Payload too short');
        $iv = substr($payload, 0, $ivLen);
        $tag = substr($payload, -16);
        $ct = substr($payload, $ivLen, -16);
        $out = openssl_decrypt($ct, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag);
        if ($out === false) throw new RuntimeException('Decrypt failed');
        return $out;
    }
    $iv = $ivLen ? substr($payload, 0, $ivLen) : '';
    $ct = $ivLen ? substr($payload, $ivLen) : $payload;
    $out = openssl_decrypt($ct, $cipher, $key, OPENSSL_RAW_DATA, $ivLen ? $iv : '');
    if ($out === false) throw new RuntimeException('Decrypt failed');
    return $out;
}

// Hashing helpers
function do_hash(string $algo, string $data, bool $binary = false): string {
    if (!has_algo($algo)) throw new RuntimeException("Hash algorithm not available: {$algo}");
    return hash($algo, $data, $binary);
}
function do_file_hash(string $algo, array $file): string {
    if (($file['error'] ?? 1) !== UPLOAD_ERR_OK) throw new RuntimeException('Upload failed');
    if (!has_algo($algo)) throw new RuntimeException("Hash algorithm not available: {$algo}");
    return hash_file($algo, $file['tmp_name']);
}
function double_sha256(string $data): string { return hash('sha256', hash('sha256', $data, true)); }

// Case/convert
function to_title(string $s): string { return mb_convert_case($s, MB_CASE_TITLE, 'UTF-8'); }
function to_snake(string $s): string {
    $s = preg_replace('/[^\pL\pN]+/u', ' ', $s);
    $s = trim($s);
    $s = preg_replace('/\s+/u', '_', $s);
    return mb_strtolower($s, 'UTF-8');
}
function to_kebab(string $s): string { return str_replace('_', '-', to_snake($s)); }

// ---------- request handling ----------
$action = post('action', '');
$result = null; $error = null;

try {
    switch ($action) {
        // --- Hashing ---
        case 'hash_text':
            $algo = post('algo');
            $text = post('input');
            $bin = isset($_POST['binary']);
            $res = do_hash($algo, $text, $bin);
            $result = $bin ? base64_encode($res) : $res;
            break;
        case 'hash_double_sha256':
            $text = post('input');
            $result = double_sha256($text);
            break;
        case 'hash_file':
            $algo = post('algo_file');
            $result = do_file_hash($algo, $_FILES['file'] ?? []);
            break;

        // --- Symmetric encryption ---
        case 'aes_encrypt': {
            $mode = post('mode', 'aes-256-cbc'); // aes-128/192/256-cbc, aes-256-gcm
            $keyHex = post('key');
            $ivHex = post('iv');
            $plain = post('input');
            $isGCM = str_contains($mode, 'gcm');
            $result = cipher_encrypt($mode, $keyHex, $ivHex, $plain, $isGCM);
            break;
        }
        case 'aes_decrypt': {
            $mode = post('mode', 'aes-256-cbc');
            $keyHex = post('key');
            $payload = post('payload');
            $isGCM = str_contains($mode, 'gcm');
            $ivLen = $isGCM ? 12 : 16;
            $result = cipher_decrypt($mode, $keyHex, $payload, $isGCM, $ivLen);
            break;
        }
        case 'des_encrypt': {
            $mode = post('mode', 'des-ede3-cbc'); // des-cbc, des-ede3-cbc
            $keyHex = post('key');
            $ivHex = post('iv');
            $plain = post('input');
            $result = cipher_encrypt($mode, $keyHex, $ivHex, $plain, false);
            break;
        }
        case 'des_decrypt': {
            $mode = post('mode', 'des-ede3-cbc');
            $keyHex = post('key');
            $payload = post('payload');
            $ivLen = str_contains($mode, 'ede3') ? 8 : 8;
            $result = cipher_decrypt($mode, $keyHex, $payload, false, $ivLen);
            break;
        }
        case 'rc4_encrypt': {
            $keyHex = post('key');
            $plain = post('input');
            $result = cipher_encrypt('rc4', $keyHex, '', $plain, false);
            break;
        }
        case 'rc4_decrypt': {
            $keyHex = post('key');
            $payload = post('payload');
            // rc4 has no IV
            $result = cipher_decrypt('rc4', $keyHex, $payload, false, 0);
            break;
        }

        // --- RSA ---
        case 'rsa_generate':
            $bits = (int)post('bits', '2048');
            $keys = rsa_generate($bits);
            $result = json_encode($keys, JSON_PRETTY_PRINT);
            break;
        case 'rsa_encrypt':
            $pub = post('pub');
            $msg = post('input');
            $result = rsa_encrypt($pub, $msg);
            break;
        case 'rsa_decrypt':
            $priv = post('priv');
            $b64 = post('payload');
            $result = rsa_decrypt($priv, $b64);
            break;
        case 'rsa_sign':
            $priv = post('priv');
            $msg = post('input');
            $hash = post('hash', 'sha256');
            $result = rsa_sign($priv, $msg, $hash);
            break;
        case 'rsa_verify':
            $pub = post('pub');
            $msg = post('input');
            $sig = post('sig');
            $hash = post('hash', 'sha256');
            $result = rsa_verify($pub, $msg, $sig, $hash) ? 'VALID' : 'INVALID';
            break;

        // --- ECDSA ---
        case 'ecdsa_generate':
            $curve = post('curve', 'prime256v1');
            $keys = ecdsa_generate($curve);
            $result = json_encode($keys, JSON_PRETTY_PRINT);
            break;
        case 'ecdsa_sign':
            $priv = post('priv');
            $msg = post('input');
            $hash = post('hash', 'sha256');
            $result = ecdsa_sign($priv, $msg, $hash);
            break;
        case 'ecdsa_verify':
            $pub = post('pub');
            $msg = post('input');
            $sig = post('sig');
            $hash = post('hash', 'sha256');
            $result = ecdsa_verify($pub, $msg, $sig, $hash) ? 'VALID' : 'INVALID';
            break;

        // --- Encoding ---
        case 'hex_encode': $result = safe_hex(post('input')); break;
        case 'hex_decode': $result = from_hex(post('inputHex')); break;
        case 'base32_encode': $result = base32_encode_rfc(post('input')); break;
        case 'base32_decode': $result = base32_decode_rfc(post('inputB32')); break;
        case 'base58_encode': $result = base58_encode(post('input')); break;
        case 'base58_decode': $result = base58_decode(post('inputB58')); break;
        case 'base64_encode': $result = base64_encode(post('input')); break;
        case 'base64_decode': $tmp = base64_decode(post('inputB64'), true); if ($tmp === false) throw new RuntimeException('Invalid Base64'); $result = $tmp; break;
        case 'base64url_encode': $result = b64u_enc(post('input')); break;
        case 'base64url_decode': $result = b64u_dec(post('inputB64U')); break;
        case 'html_encode': $result = htmlentities(post('input'), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); break;
        case 'html_decode': $result = html_entity_decode(post('input'), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); break;
        case 'url_encode': $result = rawurlencode(post('input')); break;
        case 'url_decode': $result = rawurldecode(post('input')); break;

        // --- JSON/XML ---
        case 'json_pretty': $result = pretty_json(post('input')); break;
        case 'json_minify': $result = minify_json(post('input')); break;
        case 'xml_pretty': $result = pretty_xml(post('input')); break;
        case 'xml_minify': $result = minify_xml(post('input')); break;

        // --- Case / Convert ---
        case 'case_upper': $result = mb_strtoupper(post('input'), 'UTF-8'); break;
        case 'case_lower': $result = mb_strtolower(post('input'), 'UTF-8'); break;
        case 'case_title': $result = to_title(post('input')); break;
        case 'case_snake': $result = to_snake(post('input')); break;
        case 'case_kebab': $result = to_kebab(post('input')); break;

        // --- CRC (text) ---
        case 'crc32':
            $result = hash('crc32b', post('input'));
            break;

        default: /* no op */ break;
    }
} catch (Throwable $e) {
    $error = $e->getMessage();
}

function select_hash_algos(): array {
    // Curated list (only those available)
    $wanted = [
        'md5','sha1','sha224','sha256','sha384','sha512',
        'sha3-224','sha3-256','sha3-384','sha3-512',
        'ripemd160','blake2b','blake2s','crc32b'
    ];
    $available = array_map('strtolower', hash_algos());
    return array_values(array_filter($wanted, fn($a)=> in_array($a, $available,true)));
}
$hashList = select_hash_algos();

?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>CryptoPass — Hash • Encode • Crypto</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    textarea, input, select { outline: none; }
    .mono { font-family: ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace; }
  </style>
</head>
<body class="bg-gray-50 text-gray-900">
  <div class="max-w-5xl mx-auto p-6">
    <header class="mb-6">
      <h1 class="text-3xl font-semibold">CryptoPass</h1>
      <p class="text-gray-600">Hashing, encoding, and cryptography toolbox — all in one page.</p>
    </header>

    <?php if ($error): ?>
      <div class="rounded-xl bg-red-100 text-red-800 p-4 mb-4"><?= htmlspecialchars($error, ENT_QUOTES) ?></div>
    <?php endif; ?>

    <?php if ($result !== null): ?>
      <div class="rounded-xl bg-white shadow p-4 mb-6">
        <div class="text-sm text-gray-600 mb-1">Result</div>
        <textarea class="w-full mono text-sm bg-gray-50 rounded-lg p-3 h-40" readonly><?= htmlspecialchars((string)$result, ENT_QUOTES) ?></textarea>
      </div>
    <?php endif; ?>

    <div class="grid md:grid-cols-2 gap-6">
      <!-- Hashing -->
      <section class="bg-white rounded-2xl shadow p-5">
        <h2 class="text-xl font-semibold mb-3">Hash</h2>
        <form method="post" class="space-y-3">
          <input type="hidden" name="action" value="hash_text">
          <label class="block text-sm">Algorithm</label>
          <select name="algo" class="w-full rounded-lg border p-2">
            <?php foreach ($hashList as $algo): ?>
              <option value="<?= $algo ?>"><?= strtoupper($algo) ?></option>
            <?php endforeach; ?>
          </select>
          <label class="block text-sm">Text</label>
          <textarea name="input" class="w-full rounded-lg border p-3 mono" rows="4" placeholder="Message to hash"></textarea>
          <label class="inline-flex items-center gap-2">
            <input type="checkbox" name="binary" class="accent-gray-900">
            <span class="text-sm">Return raw (Base64-encoded)</span>
          </label>
          <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Compute</button>
        </form>
        <div class="border-t mt-4 pt-4 space-y-3">
          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="hash_double_sha256">
            <label class="block text-sm">Double SHA-256 (text)</label>
            <textarea name="input" class="w-full rounded-lg border p-3 mono" rows="3" placeholder="Text"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Hash x2</button>
          </form>

          <form method="post" enctype="multipart/form-data" class="space-y-2">
            <input type="hidden" name="action" value="hash_file">
            <label class="block text-sm">File hash</label>
            <select name="algo_file" class="w-full rounded-lg border p-2 mb-1">
              <?php foreach ($hashList as $algo): ?>
                <option value="<?= $algo ?>"><?= strtoupper($algo) ?></option>
              <?php endforeach; ?>
            </select>
            <input type="file" name="file" class="w-full text-sm">
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5 mt-2">Hash file</button>
          </form>

          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="crc32">
            <label class="block text-sm">CRC32 (text)</label>
            <textarea name="input" class="w-full rounded-lg border p-3 mono" rows="2" placeholder="Text"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">CRC32</button>
          </form>
        </div>
      </section>

      <!-- AES / DES / RC4 -->
      <section class="bg-white rounded-2xl shadow p-5">
        <h2 class="text-xl font-semibold mb-3">Cryptography (AES • DES/3DES • RC4)</h2>
        <div class="text-xs text-gray-500 mb-3">Keys/IV are hex. For AES-GCM use 12-byte IV (24 hex).</div>

        <form method="post" class="space-y-2">
          <input type="hidden" name="action" value="aes_encrypt">
          <label class="block text-sm">Mode</label>
          <select name="mode" class="w-full rounded-lg border p-2">
            <option value="aes-128-cbc">AES-128-CBC</option>
            <option value="aes-192-cbc">AES-192-CBC</option>
            <option value="aes-256-cbc" selected>AES-256-CBC</option>
            <option value="aes-256-gcm">AES-256-GCM</option>
          </select>
          <input name="key" class="w-full rounded-lg border p-2 mono" placeholder="Key (hex)">
          <input name="iv" class="w-full rounded-lg border p-2 mono" placeholder="IV/Nonce (hex)">
          <textarea name="input" class="w-full rounded-lg border p-3 mono" rows="3" placeholder="Plaintext"></textarea>
          <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Encrypt</button>
        </form>

        <form method="post" class="space-y-2 mt-4">
          <input type="hidden" name="action" value="aes_decrypt">
          <label class="block text-sm">Mode</label>
          <select name="mode" class="w-full rounded-lg border p-2">
            <option value="aes-128-cbc">AES-128-CBC</option>
            <option value="aes-192-cbc">AES-192-CBC</option>
            <option value="aes-256-cbc" selected>AES-256-CBC</option>
            <option value="aes-256-gcm">AES-256-GCM</option>
          </select>
          <input name="key" class="w-full rounded-lg border p-2 mono" placeholder="Key (hex)">
          <textarea name="payload" class="w-full rounded-lg border p-3 mono" rows="3" placeholder="Cipher (Base64 of IV||CT[||TAG])"></textarea>
          <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Decrypt</button>
        </form>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-3 mt-4">
          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="des_encrypt">
            <label class="block text-sm">DES / 3DES Encrypt</label>
            <select name="mode" class="w-full rounded-lg border p-2">
              <option value="des-cbc">DES-CBC</option>
              <option value="des-ede3-cbc" selected>3DES-CBC</option>
            </select>
            <input name="key" class="w-full rounded-lg border p-2 mono" placeholder="Key (hex)">
            <input name="iv" class="w-full rounded-lg border p-2 mono" placeholder="IV (hex)">
            <textarea name="input" class="w-full rounded-lg border p-3 mono" rows="2" placeholder="Plaintext"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Encrypt</button>
          </form>

          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="des_decrypt">
            <label class="block text-sm">DES / 3DES Decrypt</label>
            <select name="mode" class="w-full rounded-lg border p-2">
              <option value="des-cbc">DES-CBC</option>
              <option value="des-ede3-cbc" selected>3DES-CBC</option>
            </select>
            <input name="key" class="w-full rounded-lg border p-2 mono" placeholder="Key (hex)">
            <textarea name="payload" class="w-full rounded-lg border p-3 mono" rows="2" placeholder="Cipher (Base64 of IV||CT)"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Decrypt</button>
          </form>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-3 mt-4">
          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="rc4_encrypt">
            <label class="block text-sm">RC4 Encrypt (legacy)</label>
            <input name="key" class="w-full rounded-lg border p-2 mono" placeholder="Key (hex)">
            <textarea name="input" class="w-full rounded-lg border p-3 mono" rows="2" placeholder="Plaintext"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Encrypt</button>
          </form>
          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="rc4_decrypt">
            <label class="block text-sm">RC4 Decrypt (legacy)</label>
            <input name="key" class="w-full rounded-lg border p-2 mono" placeholder="Key (hex)">
            <textarea name="payload" class="w-full rounded-lg border p-3 mono" rows="2" placeholder="Cipher (Base64 of CT)"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Decrypt</button>
          </form>
        </div>
      </section>

      <!-- RSA / ECDSA -->
      <section class="bg-white rounded-2xl shadow p-5">
        <h2 class="text-xl font-semibold mb-3">Asymmetric (RSA • ECDSA)</h2>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="rsa_generate">
            <label class="block text-sm">Generate RSA</label>
            <input name="bits" class="w-full rounded-lg border p-2" placeholder="2048">
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Generate</button>
          </form>
          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="ecdsa_generate">
            <label class="block text-sm">Generate ECDSA</label>
            <input name="curve" class="w-full rounded-lg border p-2" placeholder="prime256v1">
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Generate</button>
          </form>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-3 mt-4">
          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="rsa_encrypt">
            <label class="block text-sm">RSA Encrypt (OAEP)</label>
            <textarea name="pub" class="w-full rounded-lg border p-2 mono" rows="3" placeholder="PEM Public Key"></textarea>
            <textarea name="input" class="w-full rounded-lg border p-2 mono" rows="2" placeholder="Plaintext (short)"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Encrypt</button>
          </form>
          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="rsa_decrypt">
            <label class="block text-sm">RSA Decrypt (OAEP)</label>
            <textarea name="priv" class="w-full rounded-lg border p-2 mono" rows="3" placeholder="PEM Private Key"></textarea>
            <textarea name="payload" class="w-full rounded-lg border p-2 mono" rows="2" placeholder="Cipher (Base64)"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Decrypt</button>
          </form>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-3 mt-4">
          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="rsa_sign">
            <label class="block text-sm">RSA Sign</label>
            <input name="hash" class="w-full rounded-lg border p-2" placeholder="sha256">
            <textarea name="priv" class="w-full rounded-lg border p-2 mono" rows="3" placeholder="PEM Private Key"></textarea>
            <textarea name="input" class="w-full rounded-lg border p-2 mono" rows="2" placeholder="Message"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Sign</button>
          </form>
          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="rsa_verify">
            <label class="block text-sm">RSA Verify</label>
            <input name="hash" class="w-full rounded-lg border p-2" placeholder="sha256">
            <textarea name="pub" class="w-full rounded-lg border p-2 mono" rows="3" placeholder="PEM Public Key"></textarea>
            <textarea name="input" class="w-full rounded-lg border p-2 mono" rows="2" placeholder="Message"></textarea>
            <textarea name="sig" class="w-full rounded-lg border p-2 mono" rows="2" placeholder="Signature (Base64)"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Verify</button>
          </form>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-3 mt-4">
          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="ecdsa_sign">
            <label class="block text-sm">ECDSA Sign</label>
            <input name="hash" class="w-full rounded-lg border p-2" placeholder="sha256">
            <textarea name="priv" class="w-full rounded-lg border p-2 mono" rows="3" placeholder="PEM Private Key (EC)"></textarea>
            <textarea name="input" class="w-full rounded-lg border p-2 mono" rows="2" placeholder="Message"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Sign</button>
          </form>
          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="ecdsa_verify">
            <label class="block text-sm">ECDSA Verify</label>
            <input name="hash" class="w-full rounded-lg border p-2" placeholder="sha256">
            <textarea name="pub" class="w-full rounded-lg border p-2 mono" rows="3" placeholder="PEM Public Key (EC)"></textarea>
            <textarea name="input" class="w-full rounded-lg border p-2 mono" rows="2" placeholder="Message"></textarea>
            <textarea name="sig" class="w-full rounded-lg border p-2 mono" rows="2" placeholder="Signature (Base64)"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Verify</button>
          </form>
        </div>
      </section>

      <!-- Encoding -->
      <section class="bg-white rounded-2xl shadow p-5">
        <h2 class="text-xl font-semibold mb-3">Encoding</h2>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="hex_encode">
            <label class="block text-sm">Hex encode</label>
            <textarea name="input" class="w-full rounded-lg border p-2 mono" rows="2"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Encode</button>
          </form>
          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="hex_decode">
            <label class="block text-sm">Hex decode</label>
            <textarea name="inputHex" class="w-full rounded-lg border p-2 mono" rows="2" placeholder="hex…"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Decode</button>
          </form>

          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="base32_encode">
            <label class="block text-sm">Base32 encode</label>
            <textarea name="input" class="w-full rounded-lg border p-2 mono" rows="2"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Encode</button>
          </form>
          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="base32_decode">
            <label class="block text-sm">Base32 decode</label>
            <textarea name="inputB32" class="w-full rounded-lg border p-2 mono" rows="2"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Decode</button>
          </form>

          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="base58_encode">
            <label class="block text-sm">Base58 encode</label>
            <textarea name="input" class="w-full rounded-lg border p-2 mono" rows="2"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Encode</button>
          </form>
          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="base58_decode">
            <label class="block text-sm">Base58 decode</label>
            <textarea name="inputB58" class="w-full rounded-lg border p-2 mono" rows="2"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Decode</button>
          </form>

          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="base64_encode">
            <label class="block text-sm">Base64 encode</label>
            <textarea name="input" class="w-full rounded-lg border p-2 mono" rows="2"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Encode</button>
          </form>
          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="base64_decode">
            <label class="block text-sm">Base64 decode</label>
            <textarea name="inputB64" class="w-full rounded-lg border p-2 mono" rows="2"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Decode</button>
          </form>

          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="base64url_encode">
            <label class="block text-sm">Base64url encode</label>
            <textarea name="input" class="w-full rounded-lg border p-2 mono" rows="2"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Encode</button>
          </form>
          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="base64url_decode">
            <label class="block text-sm">Base64url decode</label>
            <textarea name="inputB64U" class="w-full rounded-lg border p-2 mono" rows="2"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Decode</button>
          </form>

          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="html_encode">
            <label class="block text-sm">HTML entities</label>
            <textarea name="input" class="w-full rounded-lg border p-2 mono" rows="2" placeholder="<tag> & 'quotes'"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Encode</button>
          </form>
          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="html_decode">
            <label class="block text-sm">HTML decode</label>
            <textarea name="input" class="w-full rounded-lg border p-2 mono" rows="2" placeholder="&lt;tag&gt;"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Decode</button>
          </form>

          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="url_encode">
            <label class="block text-sm">URL encode</label>
            <textarea name="input" class="w-full rounded-lg border p-2 mono" rows="2" placeholder="a space &/ or ?"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Encode</button>
          </form>
          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="url_decode">
            <label class="block text-sm">URL decode</label>
            <textarea name="input" class="w-full rounded-lg border p-2 mono" rows="2" placeholder="%20 etc"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Decode</button>
          </form>
        </div>
      </section>

      <!-- JSON / XML / Case -->
      <section class="bg-white rounded-2xl shadow p-5">
        <h2 class="text-xl font-semibold mb-3">Format & Convert</h2>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="json_pretty">
            <label class="block text-sm">JSON pretty</label>
            <textarea name="input" class="w-full rounded-lg border p-2 mono" rows="3" placeholder='{"a":1}'></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Format</button>
          </form>
          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="json_minify">
            <label class="block text-sm">JSON minify</label>
            <textarea name="input" class="w-full rounded-lg border p-2 mono" rows="3"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Minify</button>
          </form>

          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="xml_pretty">
            <label class="block text-sm">XML pretty</label>
            <textarea name="input" class="w-full rounded-lg border p-2 mono" rows="3" placeholder="<root/>"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Format</button>
          </form>
          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="xml_minify">
            <label class="block text-sm">XML minify</label>
            <textarea name="input" class="w-full rounded-lg border p-2 mono" rows="3"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Minify</button>
          </form>

          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="case_upper">
            <label class="block text-sm">UPPERCASE</label>
            <textarea name="input" class="w-full rounded-lg border p-2 mono" rows="2"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Convert</button>
          </form>
          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="case_lower">
            <label class="block text-sm">lowercase</label>
            <textarea name="input" class="w-full rounded-lg border p-2 mono" rows="2"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Convert</button>
          </form>

          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="case_title">
            <label class="block text-sm">Title Case</label>
            <textarea name="input" class="w-full rounded-lg border p-2 mono" rows="2"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Convert</button>
          </form>
          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="case_snake">
            <label class="block text-sm">snake_case</label>
            <textarea name="input" class="w-full rounded-lg border p-2 mono" rows="2"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Convert</button>
          </form>

          <form method="post" class="space-y-2">
            <input type="hidden" name="action" value="case_kebab">
            <label class="block text-sm">kebab-case</label>
            <textarea name="input" class="w-full rounded-lg border p-2 mono" rows="2"></textarea>
            <button class="w-full rounded-xl bg-gray-900 text-white p-2.5">Convert</button>
          </form>
        </div>
      </section>
    </div>

    <footer class="text-xs text-gray-500 mt-10">
      <p>Security note: use test data. Some legacy algorithms (MD5, SHA-1, DES, RC4) are insecure for real protection.</p>
      <p class="mt-1">© <?= date('Y') ?> CryptoPass</p>
    </footer>
  </div>
</body>
</html>