<?php
require_once __DIR__ . '/db.php';

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

// Validates the bearer token, returns the user_id, or sends a 401 JSON response and exits.
function require_user_id(): int {
  $token = get_bearer_token();
  if (!$token || !preg_match('/^[a-f0-9]{64}$/', $token)) {
    json_response(['ok' => false, 'error' => 'missing_token'], 401);
  }
  $stmt = db()->prepare('SELECT user_id, expires_at FROM sessions WHERE id = ?');
  $stmt->execute([$token]);
  $row = $stmt->fetch();
  if (!$row) {
    json_response(['ok' => false, 'error' => 'invalid_session'], 401);
  }
  if (strtotime($row['expires_at']) < time()) {
    json_response(['ok' => false, 'error' => 'session_expired'], 401);
  }
  db()->prepare('UPDATE sessions SET last_seen_at = NOW() WHERE id = ?')->execute([$token]);
  return (int) $row['user_id'];
}

function current_session_token(): ?string {
  return get_bearer_token();
}
