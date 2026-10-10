<?php

function gki_ensure($target = null, $driver = null) {
    static $done = false;
    if ($target === null && $done) return;
    $p = $target ?: db(); if (!$p) return;
    if ($target === null) $done = true;
    if (($driver ?: db_driver()) === 'mysql') {
        $p->exec("CREATE TABLE IF NOT EXISTS globalkey_import_sources (id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, name VARCHAR(191) NOT NULL, url MEDIUMTEXT NOT NULL, enabled TINYINT(1) NOT NULL DEFAULT 1, last_status VARCHAR(40) NOT NULL DEFAULT 'new', last_count INT NOT NULL DEFAULT 0, last_error VARCHAR(255) NULL, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        $p->exec("CREATE TABLE IF NOT EXISTS globalkey_import_nodes (fingerprint CHAR(64) NOT NULL PRIMARY KEY, name VARCHAR(191) NOT NULL, uri MEDIUMTEXT NOT NULL, parsed MEDIUMTEXT NOT NULL, source_ids TEXT NOT NULL, status VARCHAR(40) NOT NULL, rtt_ms INT NULL, reason VARCHAR(255) NULL, failures INT NOT NULL DEFAULT 0, was_published TINYINT(1) NOT NULL DEFAULT 0, checked_at TIMESTAMP NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        $p->exec("CREATE TABLE IF NOT EXISTS globalkey_import_builds (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, created_epoch BIGINT NOT NULL DEFAULT 0, body MEDIUMTEXT NOT NULL, node_count INT NOT NULL, content_hash CHAR(64) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        $p->exec("CREATE TABLE IF NOT EXISTS globalkey_import_runs (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, finished_at TIMESTAMP NULL, status VARCHAR(40) NOT NULL, trigger_type VARCHAR(20) NOT NULL DEFAULT 'scheduled', source_count INT NOT NULL DEFAULT 0, found_count INT NOT NULL DEFAULT 0, unique_count INT NOT NULL DEFAULT 0, working_count INT NOT NULL DEFAULT 0, message VARCHAR(255) NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
    } else {
        $p->exec("CREATE TABLE IF NOT EXISTS globalkey_import_sources (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, url TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, last_status TEXT NOT NULL DEFAULT 'new', last_count INTEGER NOT NULL DEFAULT 0, last_error TEXT NULL, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)");
        $p->exec("CREATE TABLE IF NOT EXISTS globalkey_import_nodes (fingerprint TEXT PRIMARY KEY, name TEXT NOT NULL, uri TEXT NOT NULL, parsed TEXT NOT NULL, source_ids TEXT NOT NULL, status TEXT NOT NULL, rtt_ms INTEGER NULL, reason TEXT NULL, failures INTEGER NOT NULL DEFAULT 0, was_published INTEGER NOT NULL DEFAULT 0, checked_at TEXT NULL)");
        $p->exec("CREATE TABLE IF NOT EXISTS globalkey_import_builds (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, created_epoch INTEGER NOT NULL DEFAULT 0, body TEXT NOT NULL, node_count INTEGER NOT NULL, content_hash TEXT NOT NULL)");
        $p->exec("CREATE TABLE IF NOT EXISTS globalkey_import_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, finished_at TEXT NULL, status TEXT NOT NULL, trigger_type TEXT NOT NULL DEFAULT 'scheduled', source_count INTEGER NOT NULL DEFAULT 0, found_count INTEGER NOT NULL DEFAULT 0, unique_count INTEGER NOT NULL DEFAULT 0, working_count INTEGER NOT NULL DEFAULT 0, message TEXT NULL)");
    }
    try { $p->exec("ALTER TABLE globalkey_import_runs ADD COLUMN trigger_type " . (($driver ?: db_driver()) === 'mysql' ? "VARCHAR(20) NOT NULL DEFAULT 'scheduled'" : "TEXT NOT NULL DEFAULT 'scheduled'")); } catch (Throwable $e) {}
    try { $p->exec("ALTER TABLE globalkey_import_builds ADD COLUMN created_epoch " . (($driver ?: db_driver()) === 'mysql' ? "BIGINT NOT NULL DEFAULT 0" : "INTEGER NOT NULL DEFAULT 0")); } catch (Throwable $e) {}
    try { $p->exec("ALTER TABLE globalkey_import_nodes ADD COLUMN was_published " . (($driver ?: db_driver()) === 'mysql' ? "TINYINT(1) NOT NULL DEFAULT 0" : "INTEGER NOT NULL DEFAULT 0")); } catch (Throwable $e) {}
}

function gki_rows($table, $limit = 100, $offset = 0) {
    gki_ensure(); $p = db(); if (!$p) return [];
    $allowed = ['globalkey_import_sources', 'globalkey_import_nodes', 'globalkey_import_runs'];
    if (!in_array($table, $allowed, true)) return [];
    $order = $table === 'globalkey_import_runs' ? 'id DESC' : ($table === 'globalkey_import_sources' ? 'id' : 'name');
    return $p->query("SELECT * FROM $table ORDER BY $order LIMIT " . min(500, max(1, (int) $limit)) . ' OFFSET ' . max(0, (int) $offset))->fetchAll();
}
function gki_count($table) {
    gki_ensure(); $p = db();
    if (!$p || !in_array($table, ['globalkey_import_nodes','globalkey_import_runs'], true)) return 0;
    return (int) $p->query("SELECT COUNT(*) FROM $table")->fetchColumn();
}

function gki_source_save($id, $name, $url, $enabled, &$error = '') {
    gki_ensure(); $error = '';
    $name = trim((string) $name); $url = trim((string) $url);
    if ($name === '' || mb_strlen($name) > 191 || strlen($url) > 2048 || !gki_public_url($url)) { $error = 'Нужно указать название и публичный HTTPS URL.'; return false; }
    $p = db(); if (!$p) return false;
    if ((int) $id > 0) {
        return $p->prepare('UPDATE globalkey_import_sources SET name=?, url=?, enabled=? WHERE id=?')->execute([$name, $url, $enabled ? 1 : 0, (int) $id]);
    }
    if ((int) $p->query('SELECT COUNT(*) FROM globalkey_import_sources')->fetchColumn() >= 20) { $error = 'Допускается не более 20 источников.'; return false; }
    return $p->prepare('INSERT INTO globalkey_import_sources (name,url,enabled) VALUES (?,?,?)')->execute([$name, $url, $enabled ? 1 : 0]);
}
function gki_source_delete($id) {
    gki_ensure(); if ((int) $id <= 0 || !($p = db())) return false;
    return $p->prepare('DELETE FROM globalkey_import_sources WHERE id=?')->execute([(int) $id]);
}
function gki_public_url($url) {
    $u = parse_url((string) $url);
    if (!is_array($u) || strtolower($u['scheme'] ?? '') !== 'https' || empty($u['host']) || isset($u['user']) || isset($u['pass']) || isset($u['fragment'])) return false;
    $host = strtolower(rtrim($u['host'], '.'));
    if ($host === 'localhost' || !str_contains($host, '.') || preg_match('/\.(?:local|internal|localhost|test|invalid|example)$/', $host)) return false;
    if (filter_var($host, FILTER_VALIDATE_IP)) return gki_public_ip($host);
    return (bool) preg_match('/^[a-z0-9.-]+$/', $host);
}
function gki_public_ip($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return false;
    $number = unpack('N', inet_pton($ip))[1];
    foreach ([[0x00000000, 8], [0x64400000, 10], [0xa9fe0000, 16], [0xc0000000, 24], [0xc6120000, 15], [0xe0000000, 4]] as [$base, $prefix]) {
        $mask = (0xffffffff << (32 - $prefix)) & 0xffffffff;
        if (($number & $mask) === $base) return false;
    }
    return true;
}
function gki_fetch($url, &$error = '') {
    $error = 'source_fetch_failed';
    if (!gki_public_url($url)) { $error = 'unsafe_url'; return null; }
    $host = parse_url($url, PHP_URL_HOST);
    $ips = gethostbynamel($host) ?: [];
    if (!$ips) { $error = 'dns_failed'; return null; }
    foreach ($ips as $ip) if (!gki_public_ip($ip)) { $error = 'unsafe_dns'; return null; }
    $port = (int) (parse_url($url, PHP_URL_PORT) ?: 443);
    if ($port !== 443) { $error = 'unsupported_port'; return null; }
    $body = ''; $c = curl_init($url);
    curl_setopt_array($c, [CURLOPT_RETURNTRANSFER => false, CURLOPT_FOLLOWLOCATION => false, CURLOPT_TIMEOUT => 15,
        CURLOPT_CONNECTTIMEOUT => 5, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS, CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2, CURLOPT_RESOLVE => ["$host:443:" . $ips[0]], CURLOPT_ENCODING => '',
        CURLOPT_USERAGENT => 'SubscriptionMiddleware/GlobalKeys',
        CURLOPT_WRITEFUNCTION => function($ch, $chunk) use (&$body) { if (strlen($body) + strlen($chunk) > 2097152) return 0; $body .= $chunk; return strlen($chunk); }]);
    $ok = curl_exec($c); $code = curl_getinfo($c, CURLINFO_HTTP_CODE);
    if (!$ok || $code !== 200 || $body === '') { $error = $code >= 300 && $code < 400 ? 'redirect_rejected' : 'http_or_size_error'; return null; }
    $error = ''; return $body;
}

function gki_extract($body) {
    $python = getenv('GLOBALKEY_PYTHON') ?: 'python3';
    $cmd = [$python, __DIR__ . '/../tools/globalkey_adapter.py'];
    if (PHP_OS_FAMILY !== 'Windows') $cmd = array_merge(['timeout', '-k', '2', '15'], $cmd);
    $process = proc_open($cmd, [['pipe','r'],['pipe','w'],['pipe','w']], $pipes);
    if (!is_resource($process)) return null;
    fwrite($pipes[0], $body); fclose($pipes[0]);
    $output = stream_get_contents($pipes[1], 2097152); fclose($pipes[1]);
    stream_get_contents($pipes[2], 4096); fclose($pipes[2]);
    if (proc_close($process) !== 0) return null;
    $parsed = json_decode($output, true);
    return is_array($parsed) && isset($parsed['nodes']) ? $parsed : null;
}

function gki_check($parsed, &$rtt = null, &$reason = '') {
    $binary = getenv('GLOBALKEY_XRAY_BIN') ?: '/usr/local/bin/xray';
    if ($binary === '' || !is_file($binary) || !is_executable($binary)) { $reason = 'xray_unavailable'; return 'not_checked'; }
    $outbound = vless_to_xray($parsed, 'test');
    if (!$outbound) { $reason = 'unsupported_xray'; return 'unsupported_for_target'; }
    $socket = @stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
    if (!$socket) { $reason = 'local_port_error'; return 'check_error'; }
    $address = stream_socket_get_name($socket, false); fclose($socket);
    $port = (int) substr(strrchr($address, ':'), 1);
    $config = ['log' => ['loglevel' => 'none'], 'inbounds' => [['listen' => '127.0.0.1', 'port' => $port, 'protocol' => 'socks', 'settings' => ['auth' => 'noauth', 'udp' => false]]], 'outbounds' => [$outbound]];
    $dir = sys_get_temp_dir() . '/gki-' . bin2hex(random_bytes(8));
    if (!mkdir($dir, 0700)) { $reason = 'temp_error'; return 'check_error'; }
    $file = $dir . '/config.json'; file_put_contents($file, json_encode($config, JSON_UNESCAPED_SLASHES)); chmod($file, 0600);
    $proc = null;
    try {
        $proc = proc_open([$binary, 'run', '-config', $file], [['pipe','r'],['file', $dir . '/stdout','w'],['file', $dir . '/stderr','w']], $pipes);
        if (!is_resource($proc)) { $reason = 'xray_start_error'; return 'check_error'; }
        fclose($pipes[0]); usleep(250000);
        $url = setting('gki_check_url', 'https://www.gstatic.com/generate_204');
        if (!gki_public_url($url)) { $reason = 'unsafe_check_url'; return 'check_error'; }
        $timeout = min(20, max(2, (int) setting('gki_timeout', '5')));
        $attempts = min(3, max(1, (int) setting('gki_retries', '2')));
        for ($i = 0; $i < $attempts; $i++) {
            $c = curl_init($url);
            curl_setopt_array($c, [CURLOPT_RETURNTRANSFER => true, CURLOPT_PROXY => '127.0.0.1:' . $port,
                CURLOPT_PROXYTYPE => CURLPROXY_SOCKS5_HOSTNAME, CURLOPT_TIMEOUT => $timeout,
                CURLOPT_CONNECTTIMEOUT => $timeout, CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2]);
            $ca = getenv('GLOBALKEY_CHECK_CA_FILE');
            if ($ca && is_file($ca) && is_readable($ca)) curl_setopt($c, CURLOPT_CAINFO, $ca);
            $start = microtime(true); $result = curl_exec($c); $http = curl_getinfo($c, CURLINFO_HTTP_CODE); $curlno = curl_errno($c);
            if ($result !== false && $http === (int) setting('gki_check_code', '204')) {
                $rtt = (int) round((microtime(true) - $start) * 1000);
                $max_rtt = max(0, (int) setting('gki_max_rtt', '0'));
                if ($max_rtt && $rtt > $max_rtt) { $reason = 'rtt_threshold'; return 'unreachable'; }
                $reason = ''; return 'working';
            }
            $reason = $curlno === CURLE_OPERATION_TIMEDOUT ? 'timeout' : 'proxy_request_failed';
        }
        return $reason === 'timeout' ? 'timeout' : 'unreachable';
    } finally {
        if (is_resource($proc)) { proc_terminate($proc); proc_close($proc); }
        @unlink($file); @unlink($dir . '/stdout'); @unlink($dir . '/stderr'); @rmdir($dir);
    }
}

function gki_check_batch(array $parsed_by_fingerprint, $deadline) {
    $results = []; $pending = array_keys($parsed_by_fingerprint); $active = [];
    $expired = false;
    $limit = min(16, max(1, (int) setting('gki_concurrency', '8')));
    $settings = [];
    foreach (['gki_check_url' => 'https://www.gstatic.com/generate_204', 'gki_check_code' => '204', 'gki_timeout' => '5', 'gki_retries' => '2', 'gki_max_rtt' => '0'] as $key => $default) $settings[$key] = setting($key, $default);
    try {
        while ($pending || $active) {
            if (microtime(true) >= $deadline) { $expired = true; $pending = []; }
            while (!$expired && $pending && count($active) < $limit) {
                $fp = array_shift($pending);
                $cmd = [PHP_BINARY, '-d', 'display_errors=0', __DIR__ . '/../tools/globalkeys_check_one.php'];
                if (PHP_OS_FAMILY !== 'Windows') $cmd = array_merge(['timeout', '-k', '2', '70'], $cmd);
                $proc = proc_open($cmd, [['pipe','r'],['pipe','w'],['pipe','w']], $pipes);
                if (!is_resource($proc)) { $results[$fp] = ['status' => 'check_error', 'rtt' => null, 'reason' => 'check_start_error']; continue; }
                fwrite($pipes[0], json_encode(['parsed' => $parsed_by_fingerprint[$fp], 'settings' => $settings], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
                fclose($pipes[0]);
                stream_set_blocking($pipes[1], false); stream_set_blocking($pipes[2], false);
                $active[$fp] = [$proc, $pipes];
            }
            foreach ($active as $fp => [$proc, $pipes]) {
                $state = proc_get_status($proc);
                if ($state['running']) continue;
                $output = stream_get_contents($pipes[1], 4096);
                stream_get_contents($pipes[2], 4096);
                fclose($pipes[1]); fclose($pipes[2]); proc_close($proc);
                $result = json_decode($output, true);
                $results[$fp] = is_array($result) && isset($result['status']) ? $result : ['status' => 'check_error', 'rtt' => null, 'reason' => 'check_process_error'];
                unset($active[$fp]);
            }
            if ($active) usleep(50000);
        }
        if ($expired) throw new RuntimeException('deadline_exceeded');
        return $results;
    } finally {
        foreach ($active as [$proc, $pipes]) {
            proc_terminate($proc);
            foreach ($pipes as $pipe) if (is_resource($pipe)) fclose($pipe);
            proc_close($proc);
        }
    }
}

function gki_published_rows() {
    if (setting('gki_publish', '0') !== '1' || setting('gki_enabled', '0') !== '1') return [];
    try {
        gki_ensure(); if (!($p = db())) return [];
        $row = $p->query('SELECT * FROM globalkey_import_builds ORDER BY id DESC LIMIT 1')->fetch();
        $created = $row ? ((int) ($row['created_epoch'] ?? 0) ?: strtotime($row['created_at'])) : 0;
        if (!$row || $created < time() - max(60, (int) setting('gki_max_age', '86400'))) return [];
        $items = json_decode($row['body'], true); return is_array($items) ? $items : [];
    } catch (Throwable $e) { error_log('submw globalkey import snapshot unavailable'); return []; }
}
function gki_latest_build_rows() {
    try {
        gki_ensure(); if (!($p = db())) return [];
        $body = $p->query('SELECT body FROM globalkey_import_builds ORDER BY id DESC LIMIT 1')->fetchColumn();
        $rows = $body ? json_decode($body, true) : [];
        return is_array($rows) ? $rows : [];
    } catch (Throwable $e) { return []; }
}
function gki_template_validate($raw, &$error = '') {
    $error = '';
    if (strlen((string) $raw) > 262144) { $error = 'Шаблон превышает 256 КБ.'; return null; }
    $profile = json_decode((string) $raw, true);
    if (!is_array($profile) || array_is_list($profile) || !isset($profile['outbounds']) || !is_array($profile['outbounds'])) { $error = 'Нужен полный Xray JSON объект с массивом outbounds.'; return null; }
    $markers = 0;
    foreach ($profile['outbounds'] as $outbound) {
        if (!is_array($outbound)) { $error = 'Каждый outbound должен быть объектом.'; return null; }
        if (($outbound['tag'] ?? '') === 'globalkeys_insert') {
            if (count($outbound) !== 1) { $error = 'Точка вставки должна содержать только tag: globalkeys_insert.'; return null; }
            $markers++;
        }
    }
    if ($markers !== 1) { $error = 'Нужна ровно одна точка вставки {"tag":"globalkeys_insert"}.'; return null; }
    $other = $profile; unset($other['outbounds']);
    if (str_contains(json_encode($other), 'globalkeys_insert')) { $error = 'Ссылки на точку вставки вне outbounds не поддерживаются.'; return null; }
    return $profile;
}
function gki_template_profile($rows = null) {
    $raw = setting('gki_xray_template', ''); if ($raw === '') return null;
    $error = ''; $profile = gki_template_validate($raw, $error); if (!$profile) return null;
    if ($rows === null) $rows = gki_published_rows();
    if (!$rows) return null;
    $dynamic = [];
    foreach ($rows as $row) {
        $p = json_decode((string) ($row['parsed'] ?? ''), true);
        if (!is_array($p) || ($p['type'] ?? '') !== 'vless') continue;
        $tag = 'globalkey-' . substr(globalkeys_fingerprint($p), 0, 16);
        $outbound = vless_to_xray($p, $tag);
        if ($outbound) $dynamic[] = $outbound;
    }
    if (!$dynamic) return null;
    $out = [];
    foreach ($profile['outbounds'] as $item) {
        if (($item['tag'] ?? '') === 'globalkeys_insert') array_push($out, ...$dynamic);
        else $out[] = $item;
    }
    $profile['outbounds'] = $out;
    return $profile;
}

function gki_run($trigger = 'scheduled', $fetcher = null, $extractor = null, $checker = null) {
    if (setting('gki_enabled', '0') !== '1') return false;
    gki_ensure(); $p = db(); if (!$p) return false;
    $lock_path = dirname(__DIR__) . '/data/globalkey-import.lock';
    if (!is_dir(dirname($lock_path))) mkdir(dirname($lock_path), 0700, true);
    $lock = fopen($lock_path, 'c');
    if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) return false;
    set_setting('gki_last_run', (string) time());
    $run_id = 0;
    $deadline = microtime(true) + max(30, min(3600, (int) setting('gki_deadline', '600')));
    try {
        $p->prepare('INSERT INTO globalkey_import_runs (status,trigger_type) VALUES (?,?)')->execute(['running', $trigger]);
        $run_id = (int) $p->lastInsertId();
        $sources = $p->query('SELECT * FROM globalkey_import_sources WHERE enabled=1 ORDER BY id')->fetchAll();
        $candidates = []; $found = 0; $success = 0; $failed = 0;
        foreach ($sources as $source) {
            if (microtime(true) >= $deadline) throw new RuntimeException('deadline_exceeded');
            $error = ''; $body = $fetcher ? $fetcher($source['url'], $error) : gki_fetch($source['url'], $error);
            $result = $body !== null ? ($extractor ? $extractor($body) : gki_extract($body)) : null;
            if (!$result) {
                $failed++;
                $p->prepare('UPDATE globalkey_import_sources SET last_status=?,last_error=?,last_count=0 WHERE id=?')->execute(['error', $error ?: 'parse_error', $source['id']]);
                continue;
            }
            $success++; $found += (int) $result['found'];
            $p->prepare('UPDATE globalkey_import_sources SET last_status=?,last_error=?,last_count=? WHERE id=?')->execute(['ok', null, count($result['nodes']), $source['id']]);
            foreach (array_merge($result['nodes'], $result['skipped'] ?? []) as $node) {
                $fp = $node['fingerprint'];
                if (!isset($candidates[$fp])) $candidates[$fp] = ['node' => $node, 'sources' => []];
                $candidates[$fp]['sources'][] = (int) $source['id'];
            }
        }
        if ($failed && (!$success || setting('gki_partial', '1') !== '1')) throw new RuntimeException('sources_unavailable');
        if (!$sources) {
            // An intentional removal of every source retires the old pool.
            $p->exec('DELETE FROM globalkey_import_nodes');
            $p->prepare('INSERT INTO globalkey_import_builds (created_epoch,body,node_count,content_hash) VALUES (?,?,?,?)')->execute([time(), '[]', 0, hash('sha256', '[]')]);
            $working = 0;
        } else {
            ksort($candidates, SORT_STRING);
            $old = [];
            foreach ($p->query('SELECT fingerprint,status,failures,was_published FROM globalkey_import_nodes') as $row) $old[$row['fingerprint']] = $row;
            $rows = []; $working = 0; $used_names = [];
            $terminal_failure = (bool) $candidates;
            $parsed_candidates = [];
            foreach ($candidates as $fp => $entry) {
                $error = ''; $parsed = empty($entry['node']['status']) ? globalkeys_validate_single($entry['node']['uri'], $error) : null;
                if ($parsed) $parsed_candidates[$fp] = $parsed;
            }
            $checks = $checker ? $checker($parsed_candidates, $deadline) : gki_check_batch($parsed_candidates, $deadline);
            $p->beginTransaction();
            $p->exec('DELETE FROM globalkey_import_nodes');
            $insert = $p->prepare('INSERT INTO globalkey_import_nodes (fingerprint,name,uri,parsed,source_ids,status,rtt_ms,reason,failures,was_published,checked_at) VALUES (?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)');
            foreach ($candidates as $fp => $entry) {
                if (microtime(true) >= $deadline) throw new RuntimeException('deadline_exceeded');
                $node = $entry['node'];
                $parsed = $parsed_candidates[$fp] ?? null;
                $status = $parsed ? ($checks[$fp]['status'] ?? 'check_error') : ($node['status'] ?? 'invalid');
                $rtt = $checks[$fp]['rtt'] ?? null;
                $reason = $parsed ? ($checks[$fp]['reason'] ?? 'check_process_error') : ($node['reason'] ?? 'invalid_uri');
                $failures = $status === 'working' ? 0 : min(1000, (int) ($old[$fp]['failures'] ?? 0) + 1);
                $name = trim($node['name']); if ($name === '') $name = 'VLESS';
                $base = $name; $n = 2;
                while (isset($used_names[$name])) $name = $base . ' (' . $n++ . ')';
                $used_names[$name] = true;
                $allow_unchecked = $status === 'not_checked' && setting('gki_publish_unchecked', '0') === '1';
                $threshold = max(1, min(10, (int) setting('gki_failure_threshold', '2')));
                if (!in_array($status, ['timeout','unreachable','check_error'], true) || $failures < $threshold) $terminal_failure = false;
                $retain = in_array($status, ['timeout','unreachable','check_error'], true) && !empty($old[$fp]['was_published']) && $failures < $threshold;
                $publish_node = $status === 'working' || $allow_unchecked || $retain;
                $insert->execute([$fp, $name, $node['uri'], json_encode($parsed, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), json_encode($entry['sources']), $status, $rtt, $reason, $failures, $publish_node ? 1 : 0]);
                if ($publish_node) {
                    $rows[] = ['name' => $name, 'raw' => $node['uri'], 'parsed' => json_encode($parsed, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)];
                }
                if ($status === 'working') $working++;
            }
            if ($rows || ($terminal_failure && !$failed)) {
                $body = json_encode($rows, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                $p->prepare('INSERT INTO globalkey_import_builds (created_epoch,body,node_count,content_hash) VALUES (?,?,?,?)')->execute([time(), $body, count($rows), hash('sha256', $body)]);
            }
            $p->commit();
        }
        try { $p->prepare('UPDATE globalkey_import_runs SET finished_at=CURRENT_TIMESTAMP,status=?,source_count=?,found_count=?,unique_count=?,working_count=?,message=? WHERE id=?')->execute(['success', count($sources), $found, count($candidates), $working, $failed ? 'partial_source_failure' : null, $run_id]); }
        catch (Throwable $e) { error_log('submw globalkey import run log failed'); }
        try {
            $cutoff = gmdate('Y-m-d H:i:s', time() - 30 * 86400);
            $p->prepare('DELETE FROM globalkey_import_runs WHERE started_at < ?')->execute([$cutoff]);
            $p->prepare('DELETE FROM globalkey_import_builds WHERE created_at < ? AND id NOT IN (SELECT id FROM (SELECT MAX(id) AS id FROM globalkey_import_builds) AS latest)')->execute([$cutoff]);
        } catch (Throwable $e) { error_log('submw globalkey import rotation failed'); }
        set_setting('gki_last_success', (string) time());
        set_setting('gki_requested', '0');
        return true;
    } catch (Throwable $e) {
        if ($p->inTransaction()) $p->rollBack();
        $message = in_array($e->getMessage(), ['sources_unavailable', 'deadline_exceeded'], true) ? $e->getMessage() : 'build_failed';
        if ($run_id) $p->prepare('UPDATE globalkey_import_runs SET finished_at=CURRENT_TIMESTAMP,status=?,message=? WHERE id=?')->execute(['error', $message, $run_id]);
        set_setting('gki_requested', '0');
        return false;
    } finally { flock($lock, LOCK_UN); fclose($lock); }
}

function gki_test_source($id) {
    set_setting('gki_test_source_id', '0');
    gki_ensure(); $p = db(); if (!$p || (int) $id <= 0) return false;
    $st = $p->prepare('SELECT * FROM globalkey_import_sources WHERE id=?');
    $st->execute([(int) $id]); $source = $st->fetch(); if (!$source) return false;
    $error = ''; $body = gki_fetch($source['url'], $error);
    $result = $body !== null ? gki_extract($body) : null;
    $ok = is_array($result);
    $p->prepare('UPDATE globalkey_import_sources SET last_status=?,last_error=?,last_count=? WHERE id=?')->execute([$ok ? 'test_ok' : 'test_error', $ok ? null : ($error ?: 'parse_error'), $ok ? count($result['nodes']) : 0, (int) $id]);
    $p->prepare('INSERT INTO globalkey_import_runs (finished_at,status,trigger_type,source_count,found_count,unique_count,message) VALUES (CURRENT_TIMESTAMP,?,?,?,?,?,?)')->execute([$ok ? 'source_test_ok' : 'source_test_error', 'source_test', 1, $ok ? (int) $result['found'] : 0, $ok ? count($result['nodes']) : 0, $ok ? null : ($error ?: 'parse_error')]);
    return $ok;
}
