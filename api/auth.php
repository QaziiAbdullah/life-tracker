<?php
require_once __DIR__ . '/db.php';

function pseudo_session_key(): string {
  $raw = @file_get_contents('/home/u718739783/.api_token') ?: php_uname('n');
  return hash('sha256', $raw . 'redbug-pseudo-session-v1');
}

function get_bearer_token(): ?string {
  $header = null;
  if (function_exists('getallheaders')) {
    $headers = getallheaders();
    foreach ($headers as $name => $value) {
      if (strtolower($name) === 'authorization') { $header = $value; break; }
    }
  }
  if ($header === null) {
    $header = $_SERVER['HTTP_AUTHORIZATION']
      ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION']
      ?? null;
  }
  if (!$header) return null;
  if (preg_match('/Bearer\s+(.+)/i', $header, $m)) return trim($m[1]);
  return null;
}

function require_user_id(): int {
  $token = get_bearer_token();
  if (!$token) {
    json_response(['ok' => false, 'error' => 'missing_token'], 401);
  }

  // Pseudo-session path (DB not yet configured).
  if (str_starts_with($token, 'ps_')) {
    $inner = substr($token, 3);
    $dot   = strrpos($inner, '.');
    if ($dot === false) json_response(['ok' => false, 'error' => 'invalid_session'], 401);
    $payload = substr($inner, 0, $dot);
    $sig     = substr($inner, $dot + 1);
    if (!hash_equals(hash_hmac('sha256', $payload, pseudo_session_key()), $sig)) {
      json_response(['ok' => false, 'error' => 'invalid_session'], 401);
    }
    $data = json_decode(base64_decode($payload), true);
    if (!$data || empty($data['exp']) || (int) $data['exp'] < time()) {
      json_response(['ok' => false, 'error' => 'session_expired'], 401);
    }
    return 0; // synthetic user_id for pseudo-sessions
  }

  // Normal DB-backed session.
  if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
    json_response(['ok' => false, 'error' => 'missing_token'], 401);
  }
  $stmt = db()->prepare('SELECT user_id, expires_at FROM sessions WHERE id = ?');
  $stmt->execute([$token]);
  $row = $stmt->fetch();
  if (!$row) json_response(['ok' => false, 'error' => 'invalid_session'], 401);
  if (strtotime($row['expires_at']) < time()) json_response(['ok' => false, 'error' => 'session_expired'], 401);
  db()->prepare('UPDATE sessions SET last_seen_at = NOW() WHERE id = ?')->execute([$token]);
  return (int) $row['user_id'];
}

function current_session_token(): ?string {
  return get_bearer_token();
}

// Stable per-account storage key, valid for both pseudo-sessions (keyed by Google sub)
// and DB-backed sessions (keyed by numeric user_id) — used to namespace backup files.
function require_storage_key(): string {
  $token = get_bearer_token();
  if (!$token) json_response(['ok' => false, 'error' => 'missing_token'], 401);

  if (str_starts_with($token, 'ps_')) {
    $inner = substr($token, 3);
    $dot   = strrpos($inner, '.');
    if ($dot === false) json_response(['ok' => false, 'error' => 'invalid_session'], 401);
    $payload = substr($inner, 0, $dot);
    $sig     = substr($inner, $dot + 1);
    if (!hash_equals(hash_hmac('sha256', $payload, pseudo_session_key()), $sig)) {
      json_response(['ok' => false, 'error' => 'invalid_session'], 401);
    }
    $data = json_decode(base64_decode($payload), true);
    if (!$data || empty($data['exp']) || (int) $data['exp'] < time()) {
      json_response(['ok' => false, 'error' => 'session_expired'], 401);
    }
    $sub = preg_replace('/[^a-zA-Z0-9_\-]/', '', $data['sub'] ?? '');
    if (!$sub) json_response(['ok' => false, 'error' => 'invalid_session'], 401);
    return 'sub_' . $sub;
  }

  $userId = require_user_id();
  return 'uid_' . $userId;
}
