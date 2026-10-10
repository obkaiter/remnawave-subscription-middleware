<?php
// Run: php -d extension=pdo_sqlite -d extension=mbstring tests/globalkeys_regression.php
function db() { return $GLOBALS['pdo']; }
function db_driver() { return 'sqlite'; }
function setting($key, $default = null) { return $GLOBALS['settings'][$key] ?? $default; }
function set_setting($key, $value) { $GLOBALS['settings'][$key] = $value; }
function check($condition, $message) { if (!$condition) throw new RuntimeException($message); }

require dirname(__DIR__) . '/lib/vless.php';
require dirname(__DIR__) . '/lib/squadconf.php';
require dirname(__DIR__) . '/lib/globalkeys.php';
require dirname(__DIR__) . '/lib/globalkey_import.php';

$GLOBALS['pdo'] = new PDO('sqlite::memory:', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$GLOBALS['settings'] = ['globalkeys_enabled' => '1', 'gki_enabled' => '1', 'gki_publish' => '1'];
$golden = file_get_contents(__DIR__ . '/fixtures/mihomo.yaml');
$uri = 'vless://123e4567-e89b-12d3-a456-426614174001@one.example.org:443?security=tls&type=ws&path=%2Fabc#One';

$same = function ($label) use ($golden) {
    check(globalkeys_inject($golden, 'clash', 'application/yaml') === $golden, "$label: clash");
    check(globalkeys_inject($golden, 'base64', 'text/plain') === $golden, "$label: YAML body");
    check(globalkeys_inject($golden, 'base64', 'application/octet-stream') === $golden, "$label: opaque YAML");
};
$same('empty');
$error = ''; $parsed = globalkeys_parse_input($uri, $error);
check($error === '' && count($parsed) === 1, 'parse URI');
check(globalkeys_add_many($parsed, $uri, 'vless', $error), 'add URI');
$same('manual added');
$row = globalkeys_all()[0]; $id = (int) $row['id']; $version = globalkeys_version($row);
$new = str_replace('/abc', '/new', $uri);
check(globalkeys_update($id, 'Renamed', $new, $version, $error), 'edit URI: ' . $error);
$same('manual edited');
check(!globalkeys_update($id, 'Bad', 'not a URI', globalkeys_version(globalkeys_all()[0]), $error), 'invalid edit refused');
check(globalkeys_all()[0]['name'] === 'Renamed', 'invalid edit intact');
check(!globalkeys_update($id, 'Old version', $uri, $version, $error), 'optimistic lock');
globalkeys_toggle($id, false); $same('manual disabled');
globalkeys_toggle($id, true); $same('manual enabled');

gki_ensure();
$auto = [['name' => 'Auto', 'raw' => $uri, 'parsed' => json_encode($parsed[0])]];
$GLOBALS['pdo']->prepare('INSERT INTO globalkey_import_builds (body,node_count,content_hash) VALUES (?,?,?)')->execute([json_encode($auto), 1, hash('sha256', json_encode($auto))]);
$same('automatic snapshot');
$GLOBALS['settings']['gki_publish'] = '0'; $same('publish off');
$GLOBALS['settings']['gki_publish'] = '1'; $same('publish on');
$GLOBALS['settings']['gki_enabled'] = '0'; $same('import off');
$GLOBALS['settings']['gki_enabled'] = '1';
$GLOBALS['settings']['globalkeys_enabled'] = '0'; $same('master off');
$GLOBALS['settings']['globalkeys_enabled'] = '1';
globalkeys_delete($id); $same('manual removed');

$unknown = 'Something else entirely';
check(globalkeys_inject($unknown, 'base64', 'text/plain') === $unknown, 'unknown format');
$singbox = '{"outbounds":[],"route":{"rules":[]}}';
check(globalkeys_inject($singbox, 'base64', 'application/json') === $singbox, 'sing-box bypass');
$singbox_array = '[{"outbounds":[],"route":{"rules":[]}}]';
check(globalkeys_inject($singbox_array, 'base64', 'application/json') === $singbox_array, 'sing-box array bypass');
$baseline = base64_encode($uri);
check(globalkeys_inject($baseline, 'base64', 'text/plain') === $baseline, 'duplicate URI');
$plain = $uri . "\n";
check(globalkeys_inject($plain, 'base64', 'text/plain') === $plain, 'duplicate plain URI');
$different = str_replace('one.example.org', 'else.example.org', $uri);
check(str_contains(globalkeys_inject($different, 'base64', 'text/plain'), 'one.example.org'), 'plain URI injection');
$xray = '{"outbounds":[{"protocol":"freedom","tag":"direct"}],"routing":{"rules":[]}}';
check(globalkeys_inject($xray, 'base64', 'application/json') !== $xray, 'Xray injection');
$existing_xray = json_encode(['outbounds' => [vless_to_xray($parsed[0], 'existing')], 'routing' => ['rules' => []]]);
$dedup_xray = json_decode(globalkeys_inject($existing_xray, 'base64', 'application/json'), true);
check(count($dedup_xray['outbounds']) === 1, 'Xray existing outbound dedup');
$existing_array = json_encode([json_decode($existing_xray, true)]);
check(globalkeys_inject($existing_array, 'base64', 'application/json') === $existing_array, 'Xray array existing outbound dedup');
$template = '{"remarks":"Imported","outbounds":[{"protocol":"freedom","tag":"direct"},{"tag":"globalkeys_insert"}],"routing":{"rules":[{"type":"field","outboundTag":"direct"}]}}';
$err = '';
check(gki_template_validate($template, $err) !== null, 'valid Xray template: ' . $err);
check(gki_template_validate('{"outbounds":[{"tag":"globalkeys_insert"}],"routing":{"rules":[{"outboundTag":"globalkeys_insert"}]}}', $err) === null, 'dangling marker rejected');
set_setting('gki_xray_template', $template);
$array_body = '[{"remarks":"Panel","outbounds":[{"protocol":"freedom","tag":"direct"}],"routing":{"rules":[]}}]';
$result = json_decode(globalkeys_inject($array_body, 'base64', 'application/json'), true);
check(count($result) === 2, 'template appended to Xray array');
check($result[0] === json_decode($array_body, true)[0], 'panel profile preserved');
check($result[1]['routing']['rules'][0]['outboundTag'] === 'direct', 'template routing preserved');
check(count($result[1]['outbounds']) === 2, 'dynamic outbound inserted');

$profile = '{"remarks":"Full","outbounds":[{"protocol":"vless","tag":"a","settings":{"vnext":[{"address":"one.example.org","port":443,"users":[{"id":"123e4567-e89b-12d3-a456-426614174001"}]}]}}],"routing":{"rules":[]},"observatory":{"subjectSelector":["a"]}}';
$items = globalkeys_parse_input($profile, $err);
check(count($items) === 1 && ($items[0]['type'] ?? '') === 'xray_profile', 'full profile parsed as one');
check(globalkeys_add_many($items, $profile, 'xray_json', $err), 'full profile added');
$p_row = globalkeys_all()[0];
$edited = str_replace('"subjectSelector":["a"]', '"subjectSelector":["a","b"]', $profile);
check(globalkeys_update((int) $p_row['id'], 'Full edited', $edited, globalkeys_version($p_row), $err), 'full profile edit');
check(globalkeys_all()[0]['raw'] === $edited, 'full profile raw preserved');
$large_profile = json_decode($profile, true);
$large_profile['remarks'] = str_repeat('x', 300000);
$large_raw = json_encode($large_profile);
check(strlen($large_raw) > 262144, 'large profile exceeds former manual limit');
check(globalkeys_validate_single($large_raw, $err) !== null, 'large manual profile accepted: ' . $err);
$p_row = globalkeys_all()[0];
check(globalkeys_update((int) $p_row['id'], 'Large profile', $large_raw, globalkeys_version($p_row), $err), 'large manual profile saved: ' . $err);
check(globalkeys_all()[0]['raw'] === $large_raw, 'large manual profile raw preserved');
$large_items = globalkeys_parse_input($large_raw, $err);
check(count($large_items) === 1 && $err === '', 'large manual import parsed');
check(globalkeys_add_many($large_items, $large_raw, 'xray_json', $err), 'large manual import saved: ' . $err);
$added_rows = globalkeys_all();
$added_row = end($added_rows);
check($added_row['raw'] === $large_raw, 'large manual import raw preserved');
globalkeys_delete((int) $added_row['id']);

check(!gki_public_url('http://example.org/key'), 'HTTP disabled');
check(!gki_public_url('https://127.0.0.1/key'), 'loopback blocked');
check(!gki_public_url('https://169.254.169.254/key'), 'metadata blocked');
check(!gki_public_ip('100.65.1.1'), 'shared range blocked');
check(gki_public_url('https://public.example.org/key'), 'public URL accepted syntactically');
putenv('GLOBALKEY_XRAY_BIN=');
$reason = ''; $rtt = null;
check(gki_check($parsed[0], $rtt, $reason) === 'not_checked' && $reason === 'xray_unavailable', 'missing core is not working');
$batch = gki_check_batch(['one' => $parsed[0], 'two' => $parsed[0]], microtime(true) + 10);
check(($batch['one']['status'] ?? '') === 'not_checked' && ($batch['two']['status'] ?? '') === 'not_checked', 'parallel checks fail closed without core');
check(gki_run('test'), 'empty source list retires pool');
check(gki_published_rows() === [], 'empty source pool not published');
$old_body = json_encode($auto);
$GLOBALS['pdo']->prepare('INSERT INTO globalkey_import_builds (body,node_count,content_hash) VALUES (?,?,?)')->execute([$old_body, 1, hash('sha256', $old_body)]);
$GLOBALS['pdo']->prepare('INSERT INTO globalkey_import_sources (name,url) VALUES (?,?)')->execute(['bad', 'https://127.0.0.1/private']);
check(!gki_run('test'), 'unsafe source fails build');
check(gki_published_rows() === $auto, 'last known good survives failed source');
$same('failed source fallback');

// The worker's network, parser, and checker seams are replaced with local
// fixtures so aggregation, exact dedup, partial failure and deletion are tested
// without real subscriptions or proxy endpoints.
$GLOBALS['pdo']->exec('DELETE FROM globalkey_import_sources');
$GLOBALS['pdo']->exec('DELETE FROM globalkey_import_builds');
$GLOBALS['pdo']->exec('DELETE FROM globalkey_import_nodes');
check(gki_source_save(0, 'A', 'https://a.example.org/sub', true, $error), 'source A saved');
check(gki_source_save(0, 'B', 'https://b.example.org/sub', true, $error), 'source B saved');
$uri_a = str_replace('one.example.org', 'a.example.org', $uri);
$uri_b = str_replace('one.example.org', 'b.example.org', $uri);
$uri_shared = str_replace('one.example.org', 'shared.example.org', $uri);
$mk = fn($u) => ['fingerprint' => hash('sha256', $u), 'name' => 'Same', 'uri' => $u];
$fixtures = ['A' => [$mk($uri_a), $mk($uri_shared)], 'B' => [$mk($uri_shared), $mk($uri_b)]];
$fail_b = false;
$fetch = function($url, &$err) use (&$fail_b) { if ($fail_b && str_contains($url, 'b.example.org')) { $err = 'fixture_error'; return null; } return str_contains($url, 'a.example.org') ? 'A' : 'B'; };
$extract = fn($body) => ['nodes' => $fixtures[$body], 'skipped' => [], 'found' => count($fixtures[$body])];
$check = function($items, $deadline) { $out = []; foreach ($items as $fp => $item) $out[$fp] = ['status' => 'working', 'rtt' => 10, 'reason' => '']; return $out; };
check(gki_run('test', $fetch, $extract, $check), 'two-source build');
check(count(gki_published_rows()) === 3, 'N+M minus duplicate');
$shared_sources = $GLOBALS['pdo']->prepare('SELECT source_ids FROM globalkey_import_nodes WHERE fingerprint=?');
$shared_sources->execute([hash('sha256', $uri_shared)]);
check(count(json_decode($shared_sources->fetchColumn(), true)) === 2, 'duplicate remembers both sources');
$body1 = $GLOBALS['pdo']->query('SELECT body FROM globalkey_import_builds ORDER BY id DESC LIMIT 1')->fetchColumn();
check(gki_run('test', $fetch, $extract, $check), 'repeat build');
check($GLOBALS['pdo']->query('SELECT body FROM globalkey_import_builds ORDER BY id DESC LIMIT 1')->fetchColumn() === $body1, 'stable snapshot');
$fail_b = true;
check(gki_run('test', $fetch, $extract, $check), 'partial failure allowed');
check(count(gki_published_rows()) === 2, 'working source retained after partial failure');
$partial_body = $GLOBALS['pdo']->query('SELECT body FROM globalkey_import_builds ORDER BY id DESC LIMIT 1')->fetchColumn();
set_setting('gki_partial', '0');
check(!gki_run('test', $fetch, $extract, $check), 'strict policy rejects partial build');
check($GLOBALS['pdo']->query('SELECT body FROM globalkey_import_builds ORDER BY id DESC LIMIT 1')->fetchColumn() === $partial_body, 'strict policy keeps prior snapshot');
set_setting('gki_partial', '1');
$fail_b = false;
$source_a = (int) $GLOBALS['pdo']->query("SELECT id FROM globalkey_import_sources WHERE name='A'")->fetchColumn();
check(gki_source_delete($source_a), 'source deleted');
check(gki_run('test', $fetch, $extract, $check), 'build after deletion');
check(count(gki_published_rows()) === 2, 'deleted source unique key removed');
$same('multiple sources and deletion');
$unreachable = function($items, $deadline) { $out = []; foreach ($items as $fp => $item) $out[$fp] = ['status' => 'unreachable', 'rtt' => null, 'reason' => 'proxy_request_failed']; return $out; };
check(gki_run('test', $fetch, $extract, $unreachable), 'first failure cycle');
check(count(gki_published_rows()) === 2, 'first failure retains prior nodes');
check(gki_run('test', $fetch, $extract, $unreachable), 'second failure cycle');
check(gki_published_rows() === [], 'failure threshold retires auto pool');
$same('failed health checks');
echo "globalkeys regression OK\n";
