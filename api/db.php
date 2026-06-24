<?php
// Never echo raw PHP warnings/notices into what's supposed to be a clean JSON response —
// log them server-side instead so nothing about file paths/config ever reaches the client.
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

// Catch anything uncaught (DB connection failures, etc.) so the client always gets clean JSON
// instead of a raw PHP error page that could leak file paths or other internals.
set_exception_handler(function (Throwable $e) {
  error_log($e->getMessage());
  if (!headers_sent()) {
    http_response_code(500);
    header('Content-Type: application/json; charset=utf-8');
  }
  echo json_encode(['ok' => false, 'error' => 'server_error']);
  exit;
});

function db(): PDO {
  static $pdo = null;
  if ($pdo !== null) return $pdo;
  $cfg = require __DIR__ . '/config.php';
  $dsn = "mysql:host={$cfg['db_host']};dbname={$cfg['db_name']};charset=utf8mb4";
  $pdo = new PDO($dsn, $cfg['db_user'], $cfg['db_pass'], [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
  ]);
  return $pdo;
}

function config(): array {
  static $cfg = null;
  if ($cfg === null) $cfg = require __DIR__ . '/config.php';
  return $cfg;
}

function json_response($data, int $status = 200): void {
  http_response_code($status);
  header('Content-Type: application/json; charset=utf-8');
  echo json_encode($data);
  exit;
}

function json_body(): array {
  $raw = file_get_contents('php://input');
  $data = json_decode($raw, true);
  return is_array($data) ? $data : [];
}
