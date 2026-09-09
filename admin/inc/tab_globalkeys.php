<style>
.gk-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:.8rem}.gk-card{border:1px solid var(--line);border-radius:10px;padding:1rem;background:var(--bg2)}.gk-head{display:flex;align-items:center;justify-content:space-between;gap:.7rem}.gk-meta{color:var(--muted);font-size:.82rem;line-height:1.5;margin:.45rem 0}.gk-actions{display:flex;gap:.45rem;flex-wrap:wrap}.gk-actions form{display:flex;gap:.35rem}.gk-actions input{max-width:180px}
</style>
<div class="card">
    <h2 style="margin-top:0">Глобальные ключи</h2>
    <p class="muted">Эти подключения автоматически добавляются в подписки всех пользователей, кроме пользователей grace-группы.</p>
    <form method="post" data-autosave>
        <input type="hidden" name="csrf" value="<?= h($token) ?>"><input type="hidden" name="action" value="save_globalkeys">
        <div class="set-row"><div class="set-info"><div class="set-t">Добавлять глобальные ключи в подписки</div><div class="set-d">Master switch: при выключении сохранённые ключи остаются в базе, но не выдаются.</div></div><label class="switch"><input type="checkbox" name="globalkeys_enabled" <?= globalkeys_enabled() ? 'checked' : '' ?>><span class="sl"></span></label></div>
    </form>
</div>
<div class="card">
    <h3 style="margin-top:0">+ Добавить</h3>
    <form method="post" autocomplete="off">
        <input type="hidden" name="csrf" value="<?= h($token) ?>"><input type="hidden" name="action" value="add_globalkeys">
        <label for="gk_raw">VLESS URL или Xray JSON</label>
        <textarea id="gk_raw" name="raw" rows="10" spellcheck="false" placeholder="vless://…&#10;vless://…&#10;&#10;или { &quot;outbounds&quot;: […] }" style="width:100%;box-sizing:border-box;font-family:monospace"></textarea>
        <p class="muted">Несколько VLESS URL — по одному на строку. Полный Xray JSON сохраняется одним цельным профилем для Xray-подписок; одиночный outbound импортируется как VLESS. Импорт атомарный.</p>
        <button class="btn" type="submit">Добавить</button>
    </form>
</div>
<?php if (!$globalkeys_list): ?>
<div class="card"><p class="muted" style="margin:0">Глобальных ключей пока нет.</p></div>
<?php else: ?><div class="gk-grid">
<?php foreach ($globalkeys_list as $gk): $gp = json_decode((string) $gk['parsed'], true); ?>
    <div class="gk-card">
        <div class="gk-head"><strong><?= h($gk['name'] ?: 'VLESS') ?></strong><span><?= (int) $gk['enabled'] === 1 ? '✓ Включён' : 'Выключен' ?></span></div>
        <div class="gk-meta"><?= h(globalkeys_summary($gp)) ?><?php if (($gp['type'] ?? '') !== 'xray_profile'): ?><br><?= h($gp['host'] ?? '') ?>:<?= (int) ($gp['port'] ?? 0) ?><?php endif; ?><br>Источник: <?= h($gk['source_type']) ?></div>
        <div class="gk-actions">
            <form method="post"><input type="hidden" name="csrf" value="<?= h($token) ?>"><input type="hidden" name="action" value="toggle_globalkey"><input type="hidden" name="id" value="<?= (int) $gk['id'] ?>"><input type="hidden" name="enabled" value="<?= (int) $gk['enabled'] === 1 ? '0' : '1' ?>"><button class="btn ghost" type="submit"><?= (int) $gk['enabled'] === 1 ? 'Выключить' : 'Включить' ?></button></form>
            <form method="post"><input type="hidden" name="csrf" value="<?= h($token) ?>"><input type="hidden" name="action" value="move_globalkey"><input type="hidden" name="id" value="<?= (int) $gk['id'] ?>"><button class="btn ghost" name="direction" value="up" type="submit">↑</button><button class="btn ghost" name="direction" value="down" type="submit">↓</button></form>
            <form method="post"><input type="hidden" name="csrf" value="<?= h($token) ?>"><input type="hidden" name="action" value="rename_globalkey"><input type="hidden" name="id" value="<?= (int) $gk['id'] ?>"><input name="name" value="<?= h($gk['name']) ?>" maxlength="191"><button class="btn ghost" type="submit">Изменить</button></form>
            <form method="post" onsubmit="return confirm('Удалить ключ?')"><input type="hidden" name="csrf" value="<?= h($token) ?>"><input type="hidden" name="action" value="delete_globalkey"><input type="hidden" name="id" value="<?= (int) $gk['id'] ?>"><button class="btn danger" type="submit">Удалить</button></form>
        </div>
    </div>
<?php endforeach; ?></div><?php endif; ?>
