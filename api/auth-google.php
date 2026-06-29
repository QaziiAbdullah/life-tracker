<?php
require_once __DIR__ . '/db.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
  json_response(['ok' => false, 'error' => 'method_not_allowed'], 405);
}

$pdo = db();
$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

// Rate limit: max 10 login attempts per IP per 5 minutes. Each attempt costs an outbound
// call to Google, so this is abuse/cost protection, not just brute-force protection.
// Wrapped in try/catch: this is a secondary defense, not core functionality — a DB hiccup
// here (e.g. table missing after a schema update) must never block real sign-ins.
try {
  $stmt = $pdo->prepare('SELECT COUNT(*) AS c FROM login_attempts WHERE ip = ? AND attempted_at > (NOW() - INTERVAL 5 MINUTE)');
  $stmt->execute([$ip]);
  if ((int) $stmt->fetch()['c'] >= 10) {
    json_response(['ok' => false, 'error' => 'too_many_attempts'], 429);
  }
  $pdo->prepare('INSERT INTO login_attempts (ip) VALUES (?)')->execute([$ip]);
} catch (Throwable $e) {
  error_log('login_attempts rate-limit check failed (non-fatal): ' . $e->getMessage());
}

$body = json_body();
$idToken = $body['id_token'] ?? '';
if (!$idToken) {
  json_response(['ok' => false, 'error' => 'missing_id_token'], 400);
}

// Verify the Google ID token via Google's tokeninfo endpoint.
// (No Composer/JWKS library needed — fine for shared hosting; cost is bounded to login frequency.)
$verifyUrl = 'https://oauth2.googleapis.com/tokeninfo?id_token=' . urlencode($idToken);
$ch = curl_init($verifyUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 8);
$resp = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($resp === false || $httpCode !== 200) {
  json_response(['ok' => false, 'error' => 'invalid_token'], 401);
}

$claims = json_decode($resp, true);
$cfg = config();

if (!is_array($claims) || empty($claims['sub']) || empty($claims['aud'])) {
  json_response(['ok' => false, 'error' => 'invalid_token'], 401);
}
if ($claims['aud'] !== $cfg['google_client_id']) {
  json_response(['ok' => false, 'error' => 'audience_mismatch'], 401);
}
$issuer = $claims['iss'] ?? '';
if ($issuer !== 'https://accounts.google.com' && $issuer !== 'accounts.google.com') {
  json_response(['ok' => false, 'error' => 'invalid_issuer'], 401);
}
if (isset($claims['exp']) && (int) $claims['exp'] < time()) {
  json_response(['ok' => false, 'error' => 'token_expired'], 401);
}
// Google only sets this true once the user's email is actually verified — don't let an
// unverified address (which anyone could put on a Google account) onto the allow-list check.
if (isset($claims['email_verified']) && $claims['email_verified'] !== 'true' && $claims['email_verified'] !== true) {
  json_response(['ok' => false, 'error' => 'email_not_verified'], 401);
}

$googleSub = $claims['sub'];
$email = substr((string) ($claims['email'] ?? ''), 0, 255);
$displayName = substr((string) ($claims['name'] ?? ($claims['given_name'] ?? $email)), 0, 255);

$allowedEmails = $cfg['allowed_emails'] ?? [];
if (!empty($allowedEmails) && !in_array(strtolower($email), array_map('strtolower', $allowedEmails), true)) {
  json_response(['ok' => false, 'error' => 'not_authorized'], 403);
}

$stmt = $pdo->prepare('SELECT id, display_name FROM users WHERE google_sub = ?');
$stmt->execute([$googleSub]);
$user = $stmt->fetch();

if ($user) {
  $userId = (int) $user['id'];
  $finalDisplayName = $user['display_name'] ?? $displayName;
  $pdo->prepare('UPDATE users SET email = ?, last_login_at = NOW() WHERE id = ?')
      ->execute([$email, $userId]);
} else {
  $finalDisplayName = $displayName;
  $pdo->prepare('INSERT INTO users (google_sub, email, display_name, last_login_at) VALUES (?, ?, ?, NOW())')
      ->execute([$googleSub, $email, $displayName]);
  $userId = (int) $pdo->lastInsertId();
}

$sessionId = bin2hex(random_bytes(32));
$ttlDays = (int) ($cfg['session_ttl_days'] ?? 60);
$expiresAt = date('Y-m-d H:i:s', time() + $ttlDays * 86400);
$pdo->prepare('INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)')
    ->execute([$sessionId, $userId, $expiresAt]);

json_response([
  'ok' => true,
  'session_token' => $sessionId,
  'user' => [
    'displayName' => $finalDisplayName,
    'email' => $email,
  ],
]);
