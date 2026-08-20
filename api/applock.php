<?php
// App Lock — a second factor on top of the existing Google-session auth. Even if a device
// somehow still has a valid session token (e.g. someone signed in on it a while ago and it
// wasn't logged out), the app's actual data stays hidden behind this PIN until it's entered.
// All checks happen server-side (hash comparison, rate limiting) — the client never gets to
// decide "am I unlocked", only this endpoint does.
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/auth.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
  json_response(['ok' => false, 'error' => 'method_not_allowed'], 405);
}

// Idempotent self-migration — lets this ship without needing manual phpMyAdmin work. MySQL
// doesn't support "ADD COLUMN IF NOT EXISTS" on the older versions common on shared hosting,
// so each ALTER is wrapped and duplicate-column errors (1060) are swallowed.
function applock_migrate(PDO $pdo): void {
  $alters = [
    "ALTER TABLE users ADD COLUMN app_pin_hash VARCHAR(255) NULL",
    "ALTER TABLE users ADD COLUMN app_otp_hash VARCHAR(255) NULL",
    "ALTER TABLE users ADD COLUMN app_otp_expires DATETIME NULL",
  ];
  foreach ($alters as $sql) {
    try { $pdo->exec($sql); } catch (Throwable $e) {
      if (strpos($e->getMessage(), '1060') === false) { /* not a "duplicate column" error — log it, but don't block the request over a migration hiccup */ error_log('applock_migrate: ' . $e->getMessage()); }
    }
  }
}

function applock_rate_limited(PDO $pdo, string $ip): bool {
  try {
    $stmt = $pdo->prepare('SELECT COUNT(*) AS c FROM login_attempts WHERE ip = ? AND attempted_at > (NOW() - INTERVAL 10 MINUTE)');
    $stmt->execute([$ip]);
    if ((int) $stmt->fetch()['c'] >= 15) return true;
    $pdo->prepare('INSERT INTO login_attempts (ip) VALUES (?)')->execute([$ip]);
  } catch (Throwable $e) { /* rate-limit table issue is non-fatal, don't block real requests over it */ }
  return false;
}

$pdo = db();
applock_migrate($pdo);

$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$body = json_body();
$action = $body['action'] ?? '';

if ($action === 'status') {
  $userId = require_user_id();
  if ($userId === 0) json_response(['ok' => true, 'hasPin' => false]); // pseudo-session accounts can't use this feature
  $stmt = $pdo->prepare('SELECT app_pin_hash FROM users WHERE id = ?');
  $stmt->execute([$userId]);
  $row = $stmt->fetch();
  json_response(['ok' => true, 'hasPin' => !empty($row['app_pin_hash'])]);
}

if ($action === 'set') {
  $userId = require_user_id();
  if ($userId === 0) json_response(['ok' => false, 'error' => 'unsupported_session'], 400);
  $pin = (string) ($body['pin'] ?? '');
  $currentPin = (string) ($body['currentPin'] ?? '');
  if (!preg_match('/^\d{4,8}$/', $pin)) json_response(['ok' => false, 'error' => 'pin_format', 'message' => 'PIN must be 4-8 digits'], 400);

  $stmt = $pdo->prepare('SELECT app_pin_hash FROM users WHERE id = ?');
  $stmt->execute([$userId]);
  $existing = $stmt->fetch()['app_pin_hash'] ?? null;
  if ($existing) {
    if (applock_rate_limited($pdo, $ip)) json_response(['ok' => false, 'error' => 'rate_limited'], 429);
    if (!password_verify($currentPin, $existing)) json_response(['ok' => false, 'error' => 'wrong_current_pin'], 403);
  }
  $hash = password_hash($pin, PASSWORD_DEFAULT);
  $pdo->prepare('UPDATE users SET app_pin_hash = ? WHERE id = ?')->execute([$hash, $userId]);
  json_response(['ok' => true]);
}

if ($action === 'remove') {
  $userId = require_user_id();
  if ($userId === 0) json_response(['ok' => false, 'error' => 'unsupported_session'], 400);
  $currentPin = (string) ($body['currentPin'] ?? '');
  $stmt = $pdo->prepare('SELECT app_pin_hash FROM users WHERE id = ?');
  $stmt->execute([$userId]);
  $existing = $stmt->fetch()['app_pin_hash'] ?? null;
  if ($existing) {
    if (applock_rate_limited($pdo, $ip)) json_response(['ok' => false, 'error' => 'rate_limited'], 429);
    if (!password_verify($currentPin, $existing)) json_response(['ok' => false, 'error' => 'wrong_current_pin'], 403);
  }
  $pdo->prepare('UPDATE users SET app_pin_hash = NULL WHERE id = ?')->execute([$userId]);
  json_response(['ok' => true]);
}

if ($action === 'verify') {
  $userId = require_user_id();
  if ($userId === 0) json_response(['ok' => true, 'valid' => true]); // no PIN support for pseudo-sessions — nothing to verify against
  if (applock_rate_limited($pdo, $ip)) json_response(['ok' => false, 'error' => 'rate_limited', 'message' => 'Too many attempts — wait a few minutes'], 429);
  $pin = (string) ($body['pin'] ?? '');
  $stmt = $pdo->prepare('SELECT app_pin_hash FROM users WHERE id = ?');
  $stmt->execute([$userId]);
  $hash = $stmt->fetch()['app_pin_hash'] ?? null;
  if (!$hash) json_response(['ok' => true, 'valid' => true]); // no PIN set — nothing to check
  json_response(['ok' => true, 'valid' => password_verify($pin, $hash)]);
}

if ($action === 'forgot') {
  $userId = require_user_id();
  if ($userId === 0) json_response(['ok' => false, 'error' => 'unsupported_session'], 400);
  if (applock_rate_limited($pdo, $ip)) json_response(['ok' => false, 'error' => 'rate_limited'], 429);
  $stmt = $pdo->prepare('SELECT email FROM users WHERE id = ?');
  $stmt->execute([$userId]);
  $email = $stmt->fetch()['email'] ?? null;
  if (!$email) json_response(['ok' => false, 'error' => 'no_email_on_file'], 400);

  $code = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
  $hash = password_hash($code, PASSWORD_DEFAULT);
  $expires = date('Y-m-d H:i:s', time() + 600); // 10 minutes
  $pdo->prepare('UPDATE users SET app_otp_hash = ?, app_otp_expires = ? WHERE id = ?')->execute([$hash, $expires, $userId]);

  $subject = 'RedBug Life Tracking — App Lock verification code';
  $messageBody = "Your verification code is: $code\n\nThis code expires in 10 minutes. If you didn't request this, you can ignore this email.";
  $headers = "From: no-reply@" . preg_replace('/^www\./', '', $_SERVER['HTTP_HOST'] ?? 'alijtaba.online') . "\r\nContent-Type: text/plain; charset=UTF-8";
  $sent = @mail($email, $subject, $messageBody, $headers);

  json_response(['ok' => true, 'sent' => $sent]);
}

if ($action === 'reset') {
  $userId = require_user_id();
  if ($userId === 0) json_response(['ok' => false, 'error' => 'unsupported_session'], 400);
  if (applock_rate_limited($pdo, $ip)) json_response(['ok' => false, 'error' => 'rate_limited'], 429);
  $otp = (string) ($body['otp'] ?? '');
  $newPin = (string) ($body['newPin'] ?? '');
  if (!preg_match('/^\d{4,8}$/', $newPin)) json_response(['ok' => false, 'error' => 'pin_format'], 400);

  $stmt = $pdo->prepare('SELECT app_otp_hash, app_otp_expires FROM users WHERE id = ?');
  $stmt->execute([$userId]);
  $row = $stmt->fetch();
  if (!$row || !$row['app_otp_hash'] || !$row['app_otp_expires'] || strtotime($row['app_otp_expires']) < time()) {
    json_response(['ok' => false, 'error' => 'otp_expired'], 400);
  }
  if (!password_verify($otp, $row['app_otp_hash'])) {
    json_response(['ok' => false, 'error' => 'wrong_otp'], 403);
  }
  $hash = password_hash($newPin, PASSWORD_DEFAULT);
  $pdo->prepare('UPDATE users SET app_pin_hash = ?, app_otp_hash = NULL, app_otp_expires = NULL WHERE id = ?')->execute([$hash, $userId]);
  json_response(['ok' => true]);
}

// Mandatory login-time email verification — separate from the PIN's own "forgot" recovery
// flow (same underlying OTP columns, reused rather than duplicated). Fires once per fresh
// browser session right after a Google sign-in is confirmed, before any data is shown, the
// same shape as Gmail's own "enter the code we emailed you" 2-step verification.
if ($action === 'login_otp_send') {
  $userId = require_user_id();
  if ($userId === 0) json_response(['ok' => false, 'error' => 'unsupported_session'], 400);
  if (applock_rate_limited($pdo, $ip)) json_response(['ok' => false, 'error' => 'rate_limited'], 429);
  $stmt = $pdo->prepare('SELECT email FROM users WHERE id = ?');
  $stmt->execute([$userId]);
  $email = $stmt->fetch()['email'] ?? null;
  if (!$email) json_response(['ok' => false, 'error' => 'no_email_on_file'], 400);

  $code = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
  $hash = password_hash($code, PASSWORD_DEFAULT);
  $expires = date('Y-m-d H:i:s', time() + 600); // 10 minutes
  $pdo->prepare('UPDATE users SET app_otp_hash = ?, app_otp_expires = ? WHERE id = ?')->execute([$hash, $expires, $userId]);

  $subject = 'RedBug Life Tracking — sign-in verification code';
  $messageBody = "Your sign-in verification code is: $code\n\nThis code expires in 10 minutes. If you didn't try to sign in, you can ignore this email.";
  $headers = "From: no-reply@" . preg_replace('/^www\./', '', $_SERVER['HTTP_HOST'] ?? 'alijtaba.online') . "\r\nContent-Type: text/plain; charset=UTF-8";
  $sent = @mail($email, $subject, $messageBody, $headers);

  json_response(['ok' => true, 'sent' => $sent, 'email' => $email]);
}

if ($action === 'login_otp_verify') {
  $userId = require_user_id();
  if ($userId === 0) json_response(['ok' => true, 'valid' => true]); // pseudo-sessions have no OTP support to check against
  if (applock_rate_limited($pdo, $ip)) json_response(['ok' => false, 'error' => 'rate_limited'], 429);
  $otp = (string) ($body['otp'] ?? '');
  $stmt = $pdo->prepare('SELECT app_otp_hash, app_otp_expires FROM users WHERE id = ?');
  $stmt->execute([$userId]);
  $row = $stmt->fetch();
  if (!$row || !$row['app_otp_hash'] || !$row['app_otp_expires'] || strtotime($row['app_otp_expires']) < time()) {
    json_response(['ok' => false, 'error' => 'otp_expired'], 400);
  }
  $valid = password_verify($otp, $row['app_otp_hash']);
  if ($valid) {
    // One-time use — burn it immediately so the same code can't be replayed.
    $pdo->prepare('UPDATE users SET app_otp_hash = NULL, app_otp_expires = NULL WHERE id = ?')->execute([$userId]);
  }
  json_response(['ok' => true, 'valid' => $valid]);
}

json_response(['ok' => false, 'error' => 'unknown_action'], 400);
