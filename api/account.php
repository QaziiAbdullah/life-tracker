<?php
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/auth.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
  json_response(['ok' => false, 'error' => 'method_not_allowed'], 405);
}

$userId = require_user_id();
$body = json_body();
$action = $body['action'] ?? '';

if ($action === 'delete_all') {
  db()->prepare('DELETE FROM kv_store WHERE user_id = ?')->execute([$userId]);
  json_response(['ok' => true]);
}

if ($action === 'logout') {
  $token = current_session_token();
  if ($token) {
    db()->prepare('DELETE FROM sessions WHERE id = ?')->execute([$token]);
  }
  json_response(['ok' => true]);
}

json_response(['ok' => false, 'error' => 'unknown_action'], 400);
