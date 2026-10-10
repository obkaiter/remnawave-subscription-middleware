<?php
// Exercises the PHP worker's Python subprocess boundary with a local URI.
function db() { return null; }
function db_driver() { return 'sqlite'; }
function setting($key, $default = null) { return $default; }
require dirname(__DIR__) . '/lib/globalkey_import.php';
$uri = 'vless://123e4567-e89b-12d3-a456-426614174001@one.example.org:443?security=tls&type=ws&path=%2Fone#One';
$result = gki_extract($uri);
if (!is_array($result) || count($result['nodes'] ?? []) !== 1) {
    fwrite(STDERR, "PHP/Python adapter integration failed\n"); exit(1);
}
echo "PHP/Python adapter OK\n";
