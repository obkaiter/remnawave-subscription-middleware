<?php
// CLI only. This worker never fetches or writes user subscription responses.
if (PHP_SAPI !== 'cli') exit(1);
require dirname(__DIR__) . '/lib.php';
if (in_array('--daemon', $argv, true)) {
    while (true) {
        $test_source = (int) setting('gki_test_source_id', '0');
        if ($test_source > 0) gki_test_source($test_source);
        $interval = max(5, min(1440, (int) setting('gki_interval', '60'))) * 60;
        $last = (int) setting('gki_last_run', '0');
        $requested = setting('gki_requested', '0') === '1';
        if ($requested || time() >= $last + $interval) gki_run($requested ? 'manual' : 'scheduled');
        sleep(30);
    }
}
exit(gki_run('manual') ? 0 : 1);
