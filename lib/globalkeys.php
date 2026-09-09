<?php

// Global VLESS keys are stored separately so upstream squad configuration code
// remains untouched and can be merged with minimal conflicts.
function globalkeys_ensure() {
    static $done = false;
    if ($done) return;
    $done = true;
    if (!($p = db())) return;
    try {
        if (db_driver() === 'mysql') {
            $p->exec("CREATE TABLE IF NOT EXISTS global_keys (
                id INT UNSIGNED NOT NULL AUTO_INCREMENT,
                name VARCHAR(191) NULL, enabled TINYINT(1) NOT NULL DEFAULT 1,
                source_type VARCHAR(32) NOT NULL DEFAULT 'vless', raw MEDIUMTEXT NOT NULL,
                parsed MEDIUMTEXT NOT NULL, sort_order INT NOT NULL DEFAULT 0,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                PRIMARY KEY (id), KEY idx_gk_enabled (enabled, sort_order)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        } else {
            $p->exec("CREATE TABLE IF NOT EXISTS global_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NULL, enabled INTEGER NOT NULL DEFAULT 1,
                source_type TEXT NOT NULL DEFAULT 'vless', raw TEXT NOT NULL, parsed TEXT NOT NULL,
                sort_order INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )");
            $p->exec('CREATE INDEX IF NOT EXISTS idx_gk_enabled ON global_keys(enabled, sort_order)');
        }
    } catch (Throwable $e) { error_log('submw globalkeys ensure: ' . $e->getMessage()); }
}

function globalkeys_enabled() { return setting('globalkeys_enabled', '0') === '1'; }
function globalkeys_all($enabled_only = false) {
    globalkeys_ensure();
    if (!($p = db())) return [];
    try {
        $sql = 'SELECT * FROM global_keys' . ($enabled_only ? ' WHERE enabled = 1' : '') . ' ORDER BY sort_order, id';
        return $p->query($sql)->fetchAll();
    } catch (Throwable $e) { return []; }
}
function globalkeys_delete($id) {
    globalkeys_ensure();
    if (!($p = db()) || (int) $id <= 0) return false;
    try { return $p->prepare('DELETE FROM global_keys WHERE id = ?')->execute([(int) $id]); }
    catch (Throwable $e) { return false; }
}
function globalkeys_toggle($id, $enabled) {
    globalkeys_ensure();
    if (!($p = db()) || (int) $id <= 0) return false;
    try { return $p->prepare('UPDATE global_keys SET enabled = ? WHERE id = ?')->execute([$enabled ? 1 : 0, (int) $id]); }
    catch (Throwable $e) { return false; }
}
function globalkeys_move($id, $direction) {
    globalkeys_ensure(); if (!($p = db()) || (int) $id <= 0) return false;
    $rows = globalkeys_all(); $pos = null;
    foreach ($rows as $i => $r) if ((int) $r['id'] === (int) $id) { $pos = $i; break; }
    if ($pos === null) return false; $other = $direction < 0 ? $pos - 1 : $pos + 1;
    if (!isset($rows[$other])) return true;
    try {
        $p->beginTransaction();
        $st = $p->prepare('UPDATE global_keys SET sort_order = ? WHERE id = ?');
        $st->execute([(int) $rows[$other]['sort_order'], (int) $rows[$pos]['id']]);
        $st->execute([(int) $rows[$pos]['sort_order'], (int) $rows[$other]['id']]);
        $p->commit(); return true;
    } catch (Throwable $e) { if ($p->inTransaction()) $p->rollBack(); return false; }
}
function globalkeys_update_name($id, $name) {
    globalkeys_ensure();
    if (!($p = db()) || (int) $id <= 0) return false;
    try { return $p->prepare('UPDATE global_keys SET name = ? WHERE id = ?')->execute([mb_substr(trim((string) $name), 0, 191) ?: null, (int) $id]); }
    catch (Throwable $e) { return false; }
}

function globalkeys_summary($parsed) {
    if (is_array($parsed) && ($parsed['type'] ?? '') === 'xray_profile') {
        return 'Xray profile · ' . (int) ($parsed['vless_count'] ?? 0) . ' VLESS · один хост';
    }
    return squadconf_summary($parsed);
}

function globalkeys_query_uri($p) {
    $q = [];
    $map = ['net' => 'type', 'security' => 'security', 'flow' => 'flow', 'encryption' => 'encryption', 'sni' => 'sni', 'fp' => 'fp', 'pbk' => 'pbk', 'sid' => 'sid', 'spx' => 'spx', 'pqv' => 'pqv', 'pcs' => 'pcs', 'vcn' => 'vcn', 'path' => 'path', 'hostHeader' => 'host', 'serviceName' => 'serviceName', 'grpcMode' => 'mode', 'headerType' => 'headerType', 'allowInsecure' => 'allowInsecure', 'seed' => 'seed', 'mtu' => 'mtu', 'tti' => 'tti'];
    foreach ($map as $src => $dst) if (isset($p[$src]) && $p[$src] !== '' && $p[$src] !== false && $p[$src] !== 0) $q[$dst] = $p[$src] === true ? '1' : $p[$src];
    if (!empty($p['alpn'])) $q['alpn'] = implode(',', (array) $p['alpn']);
    if (!empty($p['extra'])) $q['extra'] = json_encode($p['extra'], JSON_UNESCAPED_SLASHES);
    if (!empty($p['fm'])) $q['fm'] = json_encode($p['fm'], JSON_UNESCAPED_SLASHES);
    return $q;
}
function globalkeys_make_uri($p, $remark = '') {
    if (!is_array($p) || ($p['uuid'] ?? '') === '' || ($p['host'] ?? '') === '' || (int) ($p['port'] ?? 0) <= 0) return '';
    $host = strpos((string) $p['host'], ':') !== false ? '[' . $p['host'] . ']' : $p['host'];
    $u = 'vless://' . rawurlencode((string) $p['uuid']) . '@' . $host . ':' . (int) $p['port'];
    $q = globalkeys_query_uri($p);
    if ($q) $u .= '?' . http_build_query($q, '', '&', PHP_QUERY_RFC3986);
    if ($remark !== '') $u .= '#' . rawurlencode($remark);
    return $u;
}
function globalkeys_from_xray_outbound(array $o) {
    if (($o['protocol'] ?? '') !== 'vless') return null;
    $v = $o['settings']['vnext'][0] ?? null;
    $u = $v['users'][0] ?? null;
    if (!is_array($v) || !is_array($u)) return null;
    $s = is_array($o['streamSettings'] ?? null) ? $o['streamSettings'] : [];
    $p = ['ok' => true, 'type' => 'vless', 'version' => '', 'clients' => [], 'warnings' => [], 'notes' => [],
        'uuid' => (string) ($u['id'] ?? ''), 'host' => (string) ($v['address'] ?? ''), 'port' => (int) ($v['port'] ?? 0),
        'net' => vless_net_norm($s['network'] ?? 'tcp'), 'security' => strtolower((string) ($s['security'] ?? 'none')),
        'flow' => (string) ($u['flow'] ?? ''), 'encryption' => (string) ($u['encryption'] ?? 'none'), 'sni' => '', 'alpn' => [], 'fp' => '', 'pbk' => '', 'sid' => '', 'spx' => '', 'pqv' => '', 'pcs' => '', 'vcn' => '', 'path' => '', 'hostHeader' => '', 'serviceName' => '', 'grpcMode' => '', 'xmode' => '', 'extra' => [], 'fm' => [], 'seed' => '', 'mtu' => 0, 'tti' => 0, 'headerType' => '', 'allowInsecure' => false, 'remark' => (string) ($o['tag'] ?? '')];
    if ($p['security'] === 'tls' && is_array($s['tlsSettings'] ?? null)) { $t = $s['tlsSettings']; $p['sni'] = (string) ($t['serverName'] ?? ''); $p['alpn'] = (array) ($t['alpn'] ?? []); $p['fp'] = (string) ($t['fingerprint'] ?? ''); $p['pcs'] = (string) ($t['pinnedPeerCertSha256'] ?? ''); $p['vcn'] = (string) ($t['verifyPeerCertByName'] ?? ''); }
    if ($p['security'] === 'reality' && is_array($s['realitySettings'] ?? null)) { $t = $s['realitySettings']; $p['sni'] = (string) ($t['serverName'] ?? ''); $p['fp'] = (string) ($t['fingerprint'] ?? ''); $p['pbk'] = (string) ($t['publicKey'] ?? ''); $p['sid'] = (string) ($t['shortId'] ?? ''); $p['spx'] = (string) ($t['spiderX'] ?? ''); $p['pqv'] = (string) ($t['mldsa65Verify'] ?? ''); }
    if ($p['net'] === 'ws' && is_array($s['wsSettings'] ?? null)) { $p['path'] = (string) ($s['wsSettings']['path'] ?? ''); $p['hostHeader'] = (string) ($s['wsSettings']['host'] ?? ''); }
    if ($p['net'] === 'grpc' && is_array($s['grpcSettings'] ?? null)) { $p['serviceName'] = (string) ($s['grpcSettings']['serviceName'] ?? ''); $p['grpcMode'] = !empty($s['grpcSettings']['multiMode']) ? 'multi' : ''; }
    if ($p['net'] === 'httpupgrade' && is_array($s['httpupgradeSettings'] ?? null)) { $p['path'] = (string) ($s['httpupgradeSettings']['path'] ?? ''); $p['hostHeader'] = (string) ($s['httpupgradeSettings']['host'] ?? ''); }
    if ($p['net'] === 'xhttp' && is_array($s['xhttpSettings'] ?? null)) { $p['path'] = (string) ($s['xhttpSettings']['path'] ?? ''); $p['hostHeader'] = (string) ($s['xhttpSettings']['host'] ?? ''); $p['xmode'] = (string) ($s['xhttpSettings']['mode'] ?? ''); $p['extra'] = (array) ($s['xhttpSettings']['extra'] ?? []); }
    if ($p['net'] === 'kcp' && is_array($s['kcpSettings'] ?? null)) { $p['mtu'] = (int) ($s['kcpSettings']['mtu'] ?? 0); $p['tti'] = (int) ($s['kcpSettings']['tti'] ?? 0); }
    $p['ok'] = preg_match('/^[0-9a-fA-F-]{36}$/', $p['uuid']) && $p['host'] !== '' && $p['port'] > 0 && ($p['security'] !== 'reality' || $p['pbk'] !== '');
    if ($p['ok']) { $p['clients'] = vless_clients($p); $p['notes'] = vless_core_notes($p); }
    return $p['ok'] ? $p : null;
}

function globalkeys_xray_profile(array $profile) {
    if (!isset($profile['outbounds']) || !is_array($profile['outbounds'])) return null;
    $count = 0;
    foreach ($profile['outbounds'] as $o) {
        if (is_array($o) && globalkeys_from_xray_outbound($o)) $count++;
    }
    if ($count === 0) return null;
    $name = trim((string) ($profile['remarks'] ?? ''));
    return [
        'ok' => true,
        'type' => 'xray_profile',
        'remark' => $name !== '' ? $name : 'Xray profile',
        'profile' => $profile,
        'vless_count' => $count,
        'clients' => ['Xray JSON'],
        'warnings' => [],
        'notes' => ['Профиль сохраняется целиком: routing, balancers, observatory и outbounds не разбираются на отдельные ключи.'],
    ];
}
function globalkeys_parse_input($raw, &$error = '') {
    $error = ''; $raw = trim((string) $raw); if ($raw === '') { $error = 'Вставьте VLESS URL или Xray JSON.'; return []; }
    $first = ltrim($raw)[0] ?? '';
    if ($first === '{' || $first === '[') {
        $j = json_decode($raw, true);
        if (!is_array($j) || json_last_error() !== JSON_ERROR_NONE) { $error = 'Некорректный JSON: ' . json_last_error_msg(); return []; }
        // A complete Xray config is one logical host. Its balancers and routing
        // depend on all embedded outbounds, so splitting it changes its meaning.
        if (!array_is_list($j) && isset($j['outbounds'])) {
            $profile = globalkeys_xray_profile($j);
            if (!$profile) { $error = 'В JSON не найдено ни одного VLESS outbound.'; return []; }
            return [$profile];
        }
        $obs = array_is_list($j) ? $j : [$j];
        $out = []; foreach ($obs as $o) { if (is_array($o) && ($p = globalkeys_from_xray_outbound($o))) { $p['remark'] = trim((string) ($o['tag'] ?? $p['remark'])); $out[] = $p; } }
        if (!$out) { $error = 'В JSON не найдено ни одного VLESS outbound.'; return []; }
        return $out;
    }
    $out = []; $lines = preg_split('/\r\n|\r|\n/', $raw);
    foreach ($lines as $i => $line) { $line = trim($line); if ($line === '') continue; $p = vless_parse($line); if (!$p['ok']) { $error = 'Строка ' . ($i + 1) . ': некорректный VLESS URL'; return []; } $out[] = $p; }
    if (!$out) $error = 'Не найдено ни одного VLESS URL.';
    return $out;
}
function globalkeys_fingerprint($p) {
    if (!is_array($p)) return '';
    if (($p['type'] ?? '') === 'xray_profile') {
        return hash('sha256', json_encode($p['profile'] ?? [], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    }
    $keys = ['uuid','host','port','net','security','sni','pbk','sid','path','hostHeader','serviceName','flow','encryption','fp']; $v = [];
    foreach ($keys as $k) $v[$k] = (string) ($p[$k] ?? '');
    return hash('sha256', json_encode($v, JSON_UNESCAPED_SLASHES));
}
function globalkeys_add_many(array $items, $raw_source, $source_type = 'vless', &$error = '') {
    globalkeys_ensure(); $error = ''; if (!$items || !($p = db())) { $error = 'Не удалось подготовить импорт.'; return false; }
    try {
        $p->beginTransaction(); $st = $p->prepare('INSERT INTO global_keys (name, enabled, source_type, raw, parsed, sort_order) VALUES (?, 1, ?, ?, ?, ?)');
        $order = (int) ($p->query('SELECT COALESCE(MAX(sort_order), 0) FROM global_keys')->fetchColumn() ?? 0);
        foreach ($items as $v) {
            $name = trim((string) ($v['remark'] ?? ''));
            if (($v['type'] ?? '') === 'xray_profile') {
                if ($name === '') $name = 'Xray profile';
                $stored_raw = count($items) === 1 ? (string) $raw_source : json_encode($v['profile'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                $stored_type = 'xray_profile';
            } else {
                if ($name === '') $name = 'VLESS ' . ($v['host'] ?? '');
                $stored_raw = globalkeys_make_uri($v, $name);
                if ($stored_raw === '') throw new RuntimeException('Некорректный VLESS outbound.');
                $stored_type = $source_type;
            }
            $order++;
            $st->execute([mb_substr($name, 0, 191), $stored_type, $stored_raw, json_encode($v, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), $order]);
        }
        $p->commit(); return true;
    } catch (Throwable $e) { if ($p->inTransaction()) $p->rollBack(); $error = 'Импорт не выполнен: ' . $e->getMessage(); return false; }
}
function globalkeys_user_is_grace($short) {
    $short = trim((string) $short); if ($short === '') return false;
    $local = function_exists('grace_find') ? grace_find($short) : null;
    if ($local && (int) ($local['grace_until'] ?? 0) > time()) return true;
    $uuid = function_exists('grace_squad_uuid') ? trim((string) grace_squad_uuid()) : '';
    if ($uuid !== '' && function_exists('squadconf_user_squads')) return in_array($uuid, squadconf_user_squads($short), true);
    return false;
}
function globalkeys_configs_for_injection($body, $format) {
    if (!globalkeys_enabled()) return [];
    $rows = globalkeys_all(true); if (!$rows) return [];
    $existing = [];
    // JSON bodies can be inspected losslessly; for opaque formats the existing
    // squadconf pipeline remains authoritative and the original body is kept.
    $trim = ltrim((string) $body);
    if (($trim[0] ?? '') === '{' || ($trim[0] ?? '') === '[') {
        $j = json_decode($body, true);
        $obs = isset($j['outbounds']) && is_array($j['outbounds']) ? $j['outbounds'] : [];
        foreach ($obs as $o) { $x = globalkeys_from_xray_outbound((array) $o); if ($x) $existing[globalkeys_fingerprint($x)] = true; }
    } elseif ($format !== 'clash') {
        $decoded = base64_decode(trim((string) $body), true);
        if (is_string($decoded)) foreach (preg_split('/\r\n|\r|\n/', $decoded) as $line) { $line = trim($line); if (stripos($line, 'vless://') === 0) { $x = vless_parse($line); if (!empty($x['ok'])) $existing[globalkeys_fingerprint($x)] = true; } }
    }
    $out = []; $added = [];
    foreach ($rows as $r) {
        $x = json_decode((string) ($r['parsed'] ?? ''), true); $f = globalkeys_fingerprint($x);
        if (($x['type'] ?? '') === 'xray_profile') continue;
        if ($f === '' || isset($existing[$f]) || isset($added[$f])) continue;
        $out[] = $r; $added[$f] = true;
    }
    return $out;
}
function globalkeys_xray_profiles() {
    $out = [];
    foreach (globalkeys_all(true) as $r) {
        $p = json_decode((string) ($r['parsed'] ?? ''), true);
        if (!is_array($p) || ($p['type'] ?? '') !== 'xray_profile' || !is_array($p['profile'] ?? null)) continue;
        $profile = $p['profile'];
        $name = trim((string) ($r['name'] ?? ''));
        if ($name !== '') $profile['remarks'] = $name;
        $out[] = $profile;
    }
    return $out;
}
function globalkeys_inject_xray_profiles($body, array $profiles) {
    if (!$profiles) return $body;
    $obj = json_decode((string) $body);
    // Remnawave represents several Xray hosts as an array of complete profiles.
    // A standalone object cannot safely carry another complete profile.
    if (!is_array($obj)) return $body;
    $seen = [];
    foreach ($obj as $profile) $seen[hash('sha256', json_encode($profile, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES))] = true;
    foreach ($profiles as $profile) {
        $fp = hash('sha256', json_encode($profile, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        if (isset($seen[$fp])) continue;
        $obj[] = json_decode(json_encode($profile, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        $seen[$fp] = true;
    }
    $enc = json_encode($obj, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    return $enc === false ? $body : $enc;
}
function globalkeys_inject($body, $format) {
    $cfg = globalkeys_configs_for_injection($body, $format);
    $profiles = globalkeys_xray_profiles();
    if (!$cfg && !$profiles) return $body;
    try {
        $trim = ltrim((string) $body);
        if (($trim[0] ?? '') === '{' || ($trim[0] ?? '') === '[') {
            $obj = json_decode($body, true);
            if (squadconf_is_singbox($obj)) return $cfg ? squadconf_inject_singbox($body, $cfg) : $body;
            // Global keys are independent from the optional squad xray toggle.
            if ($cfg) $body = squadconf_inject_xray_json($body, $cfg);
            return globalkeys_inject_xray_profiles($body, $profiles);
        }
        return $cfg ? squadconf_inject($body, $format, $cfg) : $body;
    } catch (Throwable $e) { error_log('submw globalkeys inject: ' . $e->getMessage()); return $body; }
}
