<?php
// Isolated health-check child. No database writes or subscription generation.
if (PHP_SAPI !== 'cli') exit(1);
$input = json_decode(stream_get_contents(STDIN, 65536), true);
if (!is_array($input) || !is_array($input['parsed'] ?? null)) exit(2);
function setting($key, $default = null) { return $GLOBALS['check_settings'][$key] ?? $default; }
$GLOBALS['check_settings'] = is_array($input['settings'] ?? null) ? $input['settings'] : [];
require dirname(__DIR__) . '/lib/vless.php';
require dirname(__DIR__) . '/lib/globalkey_import.php';
try {
    $rtt = null; $reason = '';
    $status = gki_check($input['parsed'], $rtt, $reason);
    echo json_encode(['status' => $status, 'rtt' => $rtt, 'reason' => $reason]);
} catch (Throwable $e) {
    echo json_encode(['status' => 'check_error', 'rtt' => null, 'reason' => 'check_exception']);
}
