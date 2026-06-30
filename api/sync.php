<?php
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/auth.php';

$userId = require_user_id();

// Pseudo-session (DB not yet configured): use file-based sync so cross-device
// data sharing works even without a database. Each user gets one JSON file keyed
// by their Google sub — no secrets, no DB credentials needed.
if ($userId === 0) {
  $token = get_bearer_token();
  $inner = substr($token, 3); // strip 'ps_'
  $dot   = strrpos($inner, '.');
  $payload = json_decode(base64_decode(substr($inner, 0, $dot)), true);
  $sub = preg_replace('/[^a-zA-Z0-9_\-]/', '', $payload['sub'] ?? '');
  if (!$sub) json_response(['ok' => false, 'error' => 'invalid_session'], 401);

  $dataDir  = __DIR__ . '/data';
  $dataFile = $dataDir . '/' . $sub . '.json';

  // Bootstrap data directory on first use — PHP has write access to its own files.
  if (!is_dir($dataDir)) {
    mkdir($dataDir, 0700, true);
    file_put_contents($dataDir . '/.htaccess', "Deny from all\n");
  }

  $store = is_file($dataFile)
    ? (json_decode(file_get_contents($dataFile), true) ?: [])
    : [];

  if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $since = is_numeric($_GET['since'] ?? '') ? (int) $_GET['since'] : 0;
    $nowMs = server_time_ms();
    $changes = [];
    foreach ($store as $k => $entry) {
      if (($entry['ts'] ?? 0) > $since) {
        $changes[] = ['k' => $k, 'v' => ($entry['deleted'] ?? false) ? null : $entry['v'], 'deleted' => (bool) ($entry['deleted'] ?? false)];
      }
    }
    json_response(['ok' => true, 'server_time' => $nowMs, 'changes' => $changes]);
  }

  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $body    = json_body();
    $changes = is_array($body['changes'] ?? null) ? $body['changes'] : [];
    $nowMs   = server_time_ms();
    $applied = 0;
    $maxBytes = 10 * 1024 * 1024;
    foreach ($changes as $c) {
      if (!is_array($c) || !isset($c['k'])) continue;
      $k = (string) $c['k'];
      if ($k === '' || strlen($k) > 191) continue;
      $deleted = !empty($c['deleted']);
      $v = $deleted ? null : (string) ($c['v'] ?? '');
      if (!$deleted && strlen($v ?? '') > $maxBytes) continue;
      $store[$k] = ['v' => $v, 'ts' => $nowMs, 'deleted' => $deleted];
      $applied++;
    }
    file_put_contents($dataFile, json_encode($store));
    json_response(['ok' => true, 'server_time' => $nowMs, 'applied' => $applied]);
  }

  json_response(['ok' => false, 'error' => 'method_not_allowed'], 405);
}

$pdo = db();

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
  $since = $_GET['since'] ?? '0';
  $sinceMs = is_numeric($since) ? (int) $since : 0;
  $sinceSql = $sinceMs > 0
    ? date('Y-m-d H:i:s.', intdiv($sinceMs, 1000)) . str_pad((string) ($sinceMs % 1000), 3, '0', STR_PAD_LEFT)
    : '1970-01-01 00:00:00.000';

  $stmt = $pdo->prepare('SELECT k, v, updated_at, deleted FROM kv_store WHERE user_id = ? AND updated_at > ? ORDER BY updated_at ASC');
  $stmt->execute([$userId, $sinceSql]);
  $rows = $stmt->fetchAll();

  $changes = array_map(function ($r) {
    return ['k' => $r['k'], 'v' => $r['deleted'] ? null : $r['v'], 'deleted' => (bool) $r['deleted']];
  }, $rows);

  json_response(['ok' => true, 'server_time' => server_time_ms(), 'changes' => $changes]);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $body = json_body();
  $changes = $body['changes'] ?? [];
  if (!is_array($changes)) $changes = [];

  $maxBytes = 10 * 1024 * 1024;
  $applied = 0;

  $stmt = $pdo->prepare(
    'INSERT INTO kv_store (user_id, k, v, updated_at, deleted) VALUES (?, ?, ?, NOW(3), ?)
     ON DUPLICATE KEY UPDATE v = VALUES(v), updated_at = VALUES(updated_at), deleted = VALUES(deleted)'
  );

  foreach ($changes as $c) {
    if (!is_array($c) || !isset($c['k'])) continue;
    $k = (string) $c['k'];
    if ($k === '' || strlen($k) > 191) continue;
    $deleted = !empty($c['deleted']);
    $v = $deleted ? null : (string) ($c['v'] ?? '');
    if (!$deleted && strlen($v) > $maxBytes) continue;
    $stmt->execute([$userId, $k, $v, $deleted ? 1 : 0]);
    $applied++;
  }

  json_response(['ok' => true, 'server_time' => server_time_ms(), 'applied' => $applied]);
}

json_response(['ok' => false, 'error' => 'method_not_allowed'], 405);

function server_time_ms(): int {
  return (int) round(microtime(true) * 1000);
}
