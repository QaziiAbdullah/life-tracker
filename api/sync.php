<?php
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/auth.php';

$userId = require_user_id();
$pdo = db();

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
  $since = $_GET['since'] ?? '0';
  // Client sends the ms-epoch it last saw (echoed back as server_time). Convert to a DATETIME(3) for comparison.
  $sinceMs = is_numeric($since) ? (int) $since : 0;
  $sinceSql = $sinceMs > 0
    ? date('Y-m-d H:i:s.', intdiv($sinceMs, 1000)) . str_pad((string) ($sinceMs % 1000), 3, '0', STR_PAD_LEFT)
    : '1970-01-01 00:00:00.000';

  $stmt = $pdo->prepare('SELECT k, v, updated_at, deleted FROM kv_store WHERE user_id = ? AND updated_at > ? ORDER BY updated_at ASC');
  $stmt->execute([$userId, $sinceSql]);
  $rows = $stmt->fetchAll();

  $changes = array_map(function ($r) {
    return [
      'k' => $r['k'],
      'v' => $r['deleted'] ? null : $r['v'],
      'deleted' => (bool) $r['deleted'],
    ];
  }, $rows);

  json_response([
    'ok' => true,
    'server_time' => server_time_ms(),
    'changes' => $changes,
  ]);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $body = json_body();
  $changes = $body['changes'] ?? [];
  if (!is_array($changes)) $changes = [];

  $maxBytes = 10 * 1024 * 1024; // 10MB ceiling per value, matches client-side cap
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
    if (!$deleted && strlen($v) > $maxBytes) continue; // skip oversized values, don't fail the whole batch
    $stmt->execute([$userId, $k, $v, $deleted ? 1 : 0]);
    $applied++;
  }

  json_response([
    'ok' => true,
    'server_time' => server_time_ms(),
    'applied' => $applied,
  ]);
}

json_response(['ok' => false, 'error' => 'method_not_allowed'], 405);

function server_time_ms(): int {
  return (int) round(microtime(true) * 1000);
}
