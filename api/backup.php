<?php
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/auth.php';

$storageKey = require_storage_key();

// Backups live outside public_html — same reasoning as redbug_data/: Hostinger's git
// auto-deploy deletes every untracked file under public_html on each push.
$backupRoot = dirname(dirname(__DIR__)) . '/redbug_backups';
$userDir    = $backupRoot . '/' . $storageKey;
if (!is_dir($userDir)) @mkdir($userDir, 0700, true);

$MAX_BACKUPS  = 15;             // keep the most recent 15 (WhatsApp-style rolling backups)
$MAX_BYTES    = 25 * 1024 * 1024; // 25MB ceiling per backup (base64 images etc. can add up)

$action = $_GET['action'] ?? ($_SERVER['REQUEST_METHOD'] === 'POST' ? 'create' : 'list');

function list_backups(string $dir): array {
  if (!is_dir($dir)) return [];
  $files = glob($dir . '/*.json') ?: [];
  $out = [];
  foreach ($files as $f) {
    $id = basename($f, '.json');
    $out[] = ['id' => $id, 'size' => filesize($f), 'created_at' => (int) $id];
  }
  usort($out, fn($a, $b) => $b['created_at'] <=> $a['created_at']);
  return $out;
}

if ($action === 'list') {
  json_response(['ok' => true, 'backups' => list_backups($userDir)]);
}

if ($action === 'get') {
  $id = preg_replace('/[^0-9]/', '', $_GET['id'] ?? '');
  $file = $userDir . '/' . $id . '.json';
  if (!$id || !is_file($file)) json_response(['ok' => false, 'error' => 'not_found'], 404);
  $content = file_get_contents($file);
  json_response(['ok' => true, 'id' => $id, 'data' => json_decode($content, true)]);
}

if ($action === 'delete' && $_SERVER['REQUEST_METHOD'] === 'POST') {
  $body = json_body();
  $id = preg_replace('/[^0-9]/', '', (string) ($body['id'] ?? ''));
  $file = $userDir . '/' . $id . '.json';
  if ($id && is_file($file)) unlink($file);
  json_response(['ok' => true]);
}

if ($action === 'create' && $_SERVER['REQUEST_METHOD'] === 'POST') {
  $body = json_body();
  $data = $body['data'] ?? null;
  if (!is_array($data)) json_response(['ok' => false, 'error' => 'missing_data'], 400);

  $encoded = json_encode($data);
  if ($encoded === false) json_response(['ok' => false, 'error' => 'encode_failed'], 400);
  if (strlen($encoded) > $MAX_BYTES) json_response(['ok' => false, 'error' => 'too_large'], 413);

  $id = (string) (int) round(microtime(true) * 1000);
  file_put_contents($userDir . '/' . $id . '.json', $encoded);

  // Prune to the most recent $MAX_BACKUPS.
  $all = list_backups($userDir);
  if (count($all) > $MAX_BACKUPS) {
    foreach (array_slice($all, $MAX_BACKUPS) as $old) {
      @unlink($userDir . '/' . $old['id'] . '.json');
    }
  }

  json_response(['ok' => true, 'id' => $id, 'size' => strlen($encoded), 'created_at' => (int) $id]);
}

json_response(['ok' => false, 'error' => 'method_not_allowed'], 405);
