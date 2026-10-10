<?php
// Requires a local TCP HTTP listener at GLOBALKEY_TEST_OPEN_PORT and Xray-core.
function db() { return null; }
function db_driver() { return 'sqlite'; }
function setting($key, $default = null) { return ['gki_timeout' => '2', 'gki_retries' => '1', 'gki_check_url' => getenv('GLOBALKEY_TEST_URL') ?: 'https://www.gstatic.com/generate_204'][$key] ?? $default; }
require dirname(__DIR__) . '/lib/vless.php';
require dirname(__DIR__) . '/lib/globalkey_import.php';
$port = (int) getenv('GLOBALKEY_TEST_OPEN_PORT');
if (!$port || !is_file(getenv('GLOBALKEY_XRAY_BIN') ?: '')) { fwrite(STDERR, "Set test port and Xray binary\n"); exit(2); }
$uri = "vless://123e4567-e89b-12d3-a456-426614174001@127.0.0.1:$port?security=none&type=tcp#Open%20TCP";
$parsed = vless_parse($uri);
if (empty($parsed['ok'])) { fwrite(STDERR, "parse failed\n"); exit(1); }
$rtt = null; $reason = '';
$status = gki_check($parsed, $rtt, $reason);
$expect_working = getenv('GLOBALKEY_TEST_EXPECT_WORKING') === '1';
if (($status === 'working') !== $expect_working) { fwrite(STDERR, "Unexpected proxy check: $status ($reason)\n"); exit(1); }
echo "Proxy check status: $status ($reason)\n";
