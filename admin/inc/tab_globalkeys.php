<style>
.gk-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:.8rem}.gk-card{border:1px solid var(--line);border-radius:10px;padding:1rem;background:var(--bg2)}.gk-head{display:flex;align-items:center;justify-content:space-between;gap:.7rem}.gk-meta{color:var(--muted);font-size:.82rem;line-height:1.5;margin:.45rem 0}.gk-actions{display:flex;gap:.45rem;flex-wrap:wrap}.gk-actions form{display:flex;gap:.35rem}.gk-actions input{max-width:180px}.gk-editor{margin-top:.8rem}.gk-editor textarea{width:100%;box-sizing:border-box;font-family:monospace;min-height:12rem}.gk-editor input{width:100%;box-sizing:border-box}.gk-editor .gk-status{min-height:1.4rem}.gk-squad-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:.5rem;margin:.7rem 0}.gk-squad-grid label{display:flex;align-items:center;gap:.5rem;border:1px solid var(--line);border-radius:8px;padding:.55rem .7rem;background:var(--bg2)}
</style>
<div class="card">
    <h2 style="margin-top:0">Глобальные ключи</h2>
    <p class="muted"><strong>Mihomo/Clash-подписки не изменяются разделом «Ключи».</strong> Ручные и импортируемые ключи применяются только к поддерживаемым Xray JSON и URI-подпискам для пользователей с доступом.</p>
    <p class="muted">Сортировка задаёт место ключа относительно конца исходной подписки: 0 — в конце, −1 — перед последним, −2 — перед предпоследним. Положительные числа идут в конце по возрастанию. При одинаковом числе действует порядок стрелок.</p>
    <form method="post" data-autosave>
        <input type="hidden" name="csrf" value="<?= h($token) ?>"><input type="hidden" name="action" value="save_globalkeys">
        <div class="set-row"><div class="set-info"><div class="set-t">Добавлять глобальные ключи в поддерживаемые подписки</div><div class="set-d">Главный переключатель: при выключении сохранённые ключи остаются в базе, но не выдаются.</div></div><label class="switch"><input type="checkbox" name="globalkeys_enabled" <?= globalkeys_enabled() ? 'checked' : '' ?>><span class="sl"></span></label></div>
    </form>
</div>
<div class="card">
    <h3 style="margin-top:0">Внутренние сквады для ключей</h3>
    <p class="muted">Выбор действует для всех ручных и автоматически импортированных ключей. Пользователь получит ключи, если состоит хотя бы в одном выбранном скваде. Ранее сохранённые настройки по умолчанию оставляют выдачу всем.</p>
    <form method="post" id="gk-squad-form">
        <input type="hidden" name="csrf" value="<?= h($token) ?>"><input type="hidden" name="action" value="save_globalkeys_squads">
        <label><input type="radio" name="squad_mode" value="all" <?= $gk_selected_squads === null ? 'checked' : '' ?>> Все активные пользователи (без ограничения по сквадам)</label>
        <label><input type="radio" name="squad_mode" value="selected" <?= $gk_selected_squads !== null ? 'checked' : '' ?>> Только выбранные</label>
        <?php if ($gk_squads_err !== ''): ?><p class="muted">Список сквадов недоступен: <?= h($gk_squads_err) ?></p>
        <?php elseif (!$gk_squads): ?><p class="muted">Внутренние сквады не получены. Проверьте подключение к панели.</p><?php endif; ?>
        <?php if ($gk_squads): ?><div class="gk-squad-grid">
            <?php foreach ($gk_squads as $s): ?><label><input type="checkbox" name="squads[]" value="<?= h($s['uuid']) ?>" <?= $gk_selected_squads !== null && in_array($s['uuid'], $gk_selected_squads, true) ? 'checked' : '' ?>><span><?= h($s['name']) ?> <small class="muted">· <?= (int) $s['members'] ?></small></span></label><?php endforeach; ?>
        </div><?php endif; ?>
        <?php if ($gk_selected_squads !== null): foreach (array_diff($gk_selected_squads, array_column($gk_squads, 'uuid')) as $missing): ?><p class="muted">Сохранённый сквад не найден в панели: <?= h($missing) ?></p><?php endforeach; endif; ?>
        <button class="btn" type="submit">Сохранить сквады</button>
    </form>
</div>
<script>document.querySelectorAll('#gk-squad-form input[name="squads[]"]').forEach(input=>input.addEventListener('change',()=>{document.querySelector('#gk-squad-form input[value="selected"]').checked=true;}));</script>
<div class="card">
    <h3 style="margin-top:0">+ Добавить</h3>
    <form method="post" autocomplete="off">
        <input type="hidden" name="csrf" value="<?= h($token) ?>"><input type="hidden" name="action" value="add_globalkeys">
        <label for="gk_raw">VLESS URL или Xray JSON</label>
        <textarea id="gk_raw" name="raw" rows="10" spellcheck="false" placeholder="vless://…&#10;vless://…&#10;&#10;или { &quot;outbounds&quot;: […] }" style="width:100%;box-sizing:border-box;font-family:monospace"></textarea>
        <label>Сортировка <input type="number" name="subscription_position" step="1" value="0" required></label>
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
            <form method="post"><input type="hidden" name="csrf" value="<?= h($token) ?>"><input type="hidden" name="action" value="position_globalkey"><input type="hidden" name="id" value="<?= (int) $gk['id'] ?>"><label>Сортировка <input type="number" name="subscription_position" step="1" value="<?= (int) ($gk['subscription_position'] ?? 0) ?>" required></label><button class="btn ghost" type="submit">Сохранить</button></form>
            <form method="post"><input type="hidden" name="csrf" value="<?= h($token) ?>"><input type="hidden" name="action" value="rename_globalkey"><input type="hidden" name="id" value="<?= (int) $gk['id'] ?>"><input name="name" value="<?= h($gk['name']) ?>" maxlength="191"><button class="btn ghost" type="submit">Изменить</button></form>
            <form method="post" onsubmit="return confirm('Удалить ключ?')"><input type="hidden" name="csrf" value="<?= h($token) ?>"><input type="hidden" name="action" value="delete_globalkey"><input type="hidden" name="id" value="<?= (int) $gk['id'] ?>"><button class="btn danger" type="submit">Удалить</button></form>
        </div>
        <details class="gk-editor"><summary>Редактировать</summary>
            <form method="post" class="gk-edit-form" autocomplete="off"><input type="hidden" name="csrf" value="<?= h($token) ?>"><input type="hidden" name="action" value="edit_globalkey"><input type="hidden" name="id" value="<?= (int) $gk['id'] ?>"><input type="hidden" name="version" value="<?= h(globalkeys_version($gk)) ?>">
                <label>Название</label><input name="name" maxlength="191" required value="<?= h($gk['name']) ?>">
                <label>Исходный URI или полный Xray JSON</label><textarea name="raw" spellcheck="false" required><?= h($gk['raw']) ?></textarea>
                <p class="gk-status muted" role="status"></p>
                <button class="btn ghost gk-check" type="button">Проверить синтаксис</button> <button class="btn ghost gk-format" type="button">Форматировать JSON</button> <button class="btn" type="submit">Сохранить</button> <button class="btn ghost gk-cancel" type="button">Отмена</button>
            </form>
        </details>
    </div>
<?php endforeach; ?></div><?php endif; ?>
<script>
document.querySelectorAll('.gk-edit-form').forEach(form=>{
  const initial=new FormData(form), raw=()=>form.elements.raw.value, name=()=>form.elements.name.value;
  const originalRaw=raw(), originalName=name(), status=form.querySelector('.gk-status');
  let saved=false;
  form.closest('details').addEventListener('toggle',e=>{if(!e.target.open && !saved && (raw()!==originalRaw || name()!==originalName) && !confirm('Отменить несохранённые изменения?')) e.target.open=true;});
  form.querySelector('.gk-cancel').onclick=()=>{form.elements.raw.value=originalRaw;form.elements.name.value=originalName;form.closest('details').open=false;};
  form.querySelector('.gk-format').onclick=()=>{try{form.elements.raw.value=JSON.stringify(JSON.parse(raw()),null,2);status.textContent='JSON отформатирован. Сохраните изменения.';}catch(_){status.textContent='Поле не содержит корректный JSON.';}};
  form.querySelector('.gk-check').onclick=async()=>{status.textContent='Проверка…';try{const data=new FormData();data.set('csrf',initial.get('csrf'));data.set('raw',raw());const r=await fetch('index.php?ajax=globalkey_validate',{method:'POST',body:data});const j=await r.json();status.textContent=j.ok?'Синтаксис корректен: '+j.summary:j.error;}catch(_){status.textContent='Проверка недоступна.';}};
  form.addEventListener('submit',async e=>{e.preventDefault();status.textContent='Сохранение…';try{const data=new FormData(form);data.set('xhr','1');const r=await fetch('index.php?tab=globalkeys',{method:'POST',body:data});const j=await r.json();if(j.ok){saved=true;location.reload();}else status.textContent=j.error||'Сохранение не удалось.';}catch(_){status.textContent='Сохранение недоступно.';}});
  window.addEventListener('beforeunload',e=>{if(!saved && (raw()!==originalRaw || name()!==originalName)){e.preventDefault();e.returnValue='';}});
});
</script>
<div class="card">
    <h2>Автоматический импорт ключей</h2>
    <p class="muted">Источники обрабатывает фоновый worker. Извлекаются только VLESS подключения, совместимые с текущей Xray/URI выдачей. Внешний YAML читается только как источник узлов.</p>
    <form method="post"><input type="hidden" name="csrf" value="<?= h($token) ?>"><input type="hidden" name="action" value="gki_settings">
        <label><input type="checkbox" name="enabled" <?= setting('gki_enabled','0')==='1'?'checked':'' ?>> Включить сбор</label><br>
        <label><input type="checkbox" name="publish" <?= setting('gki_publish','0')==='1'?'checked':'' ?>> Публиковать подготовленный пул в не-Mihomo подписках</label><br>
        <label><input type="checkbox" name="partial" <?= setting('gki_partial','1')==='1'?'checked':'' ?>> Разрешить частичный успех источников</label><br>
        <label><input type="checkbox" name="publish_unchecked" <?= setting('gki_publish_unchecked','0')==='1'?'checked':'' ?>> Публиковать непроверенные ключи при отсутствии Xray (риск, выключено по умолчанию)</label>
        <div class="gk-grid">
            <label>Интервал, минут <input type="number" name="interval" min="5" max="1440" value="<?= (int) setting('gki_interval','60') ?>"></label>
            <label>Тайм-аут проверки, секунд <input type="number" name="timeout" min="2" max="20" value="<?= (int) setting('gki_timeout','5') ?>"></label>
            <label>Повторы <input type="number" name="retries" min="1" max="3" value="<?= (int) setting('gki_retries','2') ?>"></label>
            <label>Параллельные проверки <input type="number" name="concurrency" min="1" max="16" value="<?= (int) setting('gki_concurrency','8') ?>"></label>
            <label>Предельный возраст сборки, секунд <input type="number" name="max_age" min="60" max="604800" value="<?= (int) setting('gki_max_age','86400') ?>"></label>
            <label>Общий дедлайн, секунд <input type="number" name="deadline" min="30" max="3600" value="<?= (int) setting('gki_deadline','600') ?>"></label>
            <label>Максимальный RTT, мс (0 — без лимита) <input type="number" name="max_rtt" min="0" max="60000" value="<?= (int) setting('gki_max_rtt','0') ?>"></label>
            <label>Исключить после неудачных циклов <input type="number" name="failure_threshold" min="1" max="10" value="<?= (int) setting('gki_failure_threshold','2') ?>"></label>
            <label>Ожидаемый HTTP код <input type="number" name="check_code" min="100" max="599" value="<?= (int) setting('gki_check_code','204') ?>"></label>
        </div>
        <label>URL проверки через прокси <input name="check_url" style="width:100%;box-sizing:border-box" value="<?= h(setting('gki_check_url','https://www.gstatic.com/generate_204')) ?>"></label>
        <button class="btn" type="submit">Сохранить настройки</button>
    </form>
    <form method="post" style="margin-top:1rem"><input type="hidden" name="csrf" value="<?= h($token) ?>"><input type="hidden" name="action" value="gki_run_now"><button class="btn ghost" type="submit">Собрать сейчас</button></form>
    <p class="muted">Последняя успешная сборка: <?= (int) setting('gki_last_success','0') ? h(date('Y-m-d H:i:s', (int) setting('gki_last_success','0'))) : 'нет' ?> · Следующий запуск: <?= (int) setting('gki_last_run','0') ? h(date('Y-m-d H:i:s', (int) setting('gki_last_run','0') + (int) setting('gki_interval','60') * 60)) : 'после запуска worker' ?> · В очереди: <?= setting('gki_requested','0')==='1'?'да':'нет' ?></p>
</div>
<div class="card">
    <h3>Источники (не более 20)</h3>
    <label>Поиск по названию <input id="gki-source-search" type="search" placeholder="Название источника"></label>
    <?php foreach ($gki_sources as $src): ?>
    <div class="gk-card gki-source-card" data-name="<?= h(mb_strtolower($src['name'])) ?>" style="margin-bottom:.5rem"><form method="post"><input type="hidden" name="csrf" value="<?= h($token) ?>"><input type="hidden" name="action" value="gki_source"><input type="hidden" name="id" value="<?= (int) $src['id'] ?>">
        <label>Название <input name="name" maxlength="191" value="<?= h($src['name']) ?>" required></label>
        <label>HTTPS URL <input name="url" type="password" autocomplete="new-password" style="width:100%;box-sizing:border-box" value="<?= h($src['url']) ?>" required></label>
        <button class="btn ghost gki-reveal" type="button">Показать URL</button>
        <label><input type="checkbox" name="enabled" <?= (int)$src['enabled']?'checked':'' ?>> Включён</label>
        <button class="btn ghost" type="submit">Сохранить</button>
        <span class="muted">Статус: <?= h($src['last_status']) ?> · узлов: <?= (int) $src['last_count'] ?> · <?= h($src['last_error'] ?? '') ?></span>
    </form><form method="post"><input type="hidden" name="csrf" value="<?= h($token) ?>"><input type="hidden" name="action" value="gki_test_source"><input type="hidden" name="id" value="<?= (int) $src['id'] ?>"><button class="btn ghost" type="submit">Тест источника</button></form><form method="post" onsubmit="return confirm('Удалить источник?')"><input type="hidden" name="csrf" value="<?= h($token) ?>"><input type="hidden" name="action" value="gki_delete_source"><input type="hidden" name="id" value="<?= (int) $src['id'] ?>"><button class="btn danger" type="submit">Удалить</button></form></div>
    <?php endforeach; ?>
    <form method="post"><input type="hidden" name="csrf" value="<?= h($token) ?>"><input type="hidden" name="action" value="gki_source"><input type="hidden" name="enabled" value="1">
        <label>Новый источник <input name="name" maxlength="191" required placeholder="Название"></label>
        <label>HTTPS URL <input name="url" type="url" style="width:100%;box-sizing:border-box" required placeholder="https://example.com/subscription/..."></label>
        <button class="btn" type="submit">Добавить источник</button>
    </form>
</div>
<script>document.getElementById('gki-source-search').addEventListener('input',e=>{const q=e.target.value.toLocaleLowerCase();document.querySelectorAll('.gki-source-card').forEach(card=>{card.hidden=!card.dataset.name.includes(q);});});document.querySelectorAll('.gki-reveal').forEach(button=>button.addEventListener('click',()=>{const input=button.closest('form').elements.url;input.type=input.type==='password'?'text':'password';button.textContent=input.type==='password'?'Показать URL':'Скрыть URL';}));</script>
<div class="card"><h3>Шаблон Xray JSON</h3>
    <p class="muted">Применяется только к ответу Xray JSON, состоящему из массива полных профилей. В массив outbounds шаблона поместите ровно один объект <code>{"tag":"globalkeys_insert"}</code>. Рабочие узлы заменят эту точку вставки; остальные секции профиля сохраняются. Очистите поле, чтобы отключить шаблон. Для URI-подписки шаблон не используется.</p>
    <form method="post"><input type="hidden" name="csrf" value="<?= h($token) ?>"><input type="hidden" name="action" value="gki_template">
        <textarea name="template" rows="12" spellcheck="false" style="width:100%;box-sizing:border-box;font-family:monospace" placeholder='{"remarks":"Импортированные ключи","outbounds":[{"tag":"globalkeys_insert"}],"routing":{"rules":[]}}'><?= h(setting('gki_xray_template','')) ?></textarea>
        <button class="btn" type="submit">Сохранить шаблон</button>
    </form>
</div>
<div class="card"><h3>Результаты и журнал</h3>
    <p class="muted">На странице до 100 узлов и 30 запусков. Секреты и полные URL в журнал не записываются.</p>
    <p>Последний снимок: <?= $gki_preview_count ?> ключей. <?php if ($gki_preview_count): ?><a href="?ajax=gki_export&amp;format=uri&amp;csrf=<?= h($token) ?>">Скачать URI</a><?php if (setting('gki_xray_template','') !== ''): ?> · <a href="?ajax=gki_export&amp;format=xray&amp;csrf=<?= h($token) ?>">Скачать Xray JSON</a><?php endif; ?><?php endif; ?></p>
    <label>Фильтр статуса узлов на странице <select id="gki-status-filter"><option value="">Все</option><option>working</option><option>unreachable</option><option>timeout</option><option>not_checked</option><option>unsupported_for_target</option><option>invalid</option><option>check_error</option></select></label>
    <div style="overflow:auto"><table><thead><tr><th>Узел</th><th>Источники</th><th>Статус</th><th>RTT</th><th>Ошибок подряд</th><th>Проверен</th><th>Причина</th></tr></thead><tbody>
    <?php foreach ($gki_nodes as $n): ?><tr class="gki-node-row" data-status="<?= h($n['status']) ?>"><td><?= h($n['name']) ?></td><td><?= h($n['source_ids']) ?></td><td><?= h($n['status']) ?></td><td><?= $n['rtt_ms']===null?'—':(int)$n['rtt_ms'].' ms' ?></td><td><?= (int)$n['failures'] ?></td><td><?= h($n['checked_at'] ?? '') ?></td><td><?= h($n['reason'] ?? '') ?></td></tr><?php endforeach; ?>
    </tbody></table></div>
    <p class="muted">Узлы: <?= $gki_node_count ?> · страница <?= $gki_page ?><?php if ($gki_page > 1): ?> · <a href="?tab=globalkeys&amp;gki_page=<?= $gki_page-1 ?>&amp;gki_run_page=<?= $gki_run_page ?>">Назад</a><?php endif; ?><?php if ($gki_page * 100 < $gki_node_count): ?> · <a href="?tab=globalkeys&amp;gki_page=<?= $gki_page+1 ?>&amp;gki_run_page=<?= $gki_run_page ?>">Далее</a><?php endif; ?></p>
    <div style="overflow:auto"><table><thead><tr><th>Время</th><th>Запуск</th><th>Статус</th><th>Источников</th><th>Найдено</th><th>Уникально</th><th>Рабочие</th><th>Сообщение</th></tr></thead><tbody>
    <?php foreach ($gki_runs as $run): ?><tr><td><?= h($run['started_at']) ?></td><td><?= h($run['trigger_type'] ?? '') ?></td><td><?= h($run['status']) ?></td><td><?= (int)$run['source_count'] ?></td><td><?= (int)$run['found_count'] ?></td><td><?= (int)$run['unique_count'] ?></td><td><?= (int)$run['working_count'] ?></td><td><?= h($run['message'] ?? '') ?></td></tr><?php endforeach; ?>
    </tbody></table></div>
    <p class="muted">Запуски: <?= $gki_run_count ?> · страница <?= $gki_run_page ?><?php if ($gki_run_page > 1): ?> · <a href="?tab=globalkeys&amp;gki_page=<?= $gki_page ?>&amp;gki_run_page=<?= $gki_run_page-1 ?>">Назад</a><?php endif; ?><?php if ($gki_run_page * 30 < $gki_run_count): ?> · <a href="?tab=globalkeys&amp;gki_page=<?= $gki_page ?>&amp;gki_run_page=<?= $gki_run_page+1 ?>">Далее</a><?php endif; ?></p>
</div>
<script>document.getElementById('gki-status-filter').addEventListener('change',e=>{const status=e.target.value;document.querySelectorAll('.gki-node-row').forEach(row=>{row.hidden=!!status&&row.dataset.status!==status;});});</script>
