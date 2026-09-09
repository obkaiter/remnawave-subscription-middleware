# Upstream synchronization

This is the downstream fork at `github.com/obkaiter/remnawave-subscription-middleware`, based on `Mrvibecodic/remnawave-subscription-middleware`. Production updates and Docker images come only from this fork.

```text
origin   https://github.com/obkaiter/remnawave-subscription-middleware.git
upstream https://github.com/Mrvibecodic/remnawave-subscription-middleware.git
```

Recommended flow: `upstream/main -> dev -> test -> pull request -> main`.

```bash
git checkout dev
git pull --ff-only origin dev
tools/sync-upstream.sh
tools/sync-upstream.sh --merge-dev
# resolve conflicts, test, then push dev and open a PR to main
git push origin dev
```

The helper refuses a dirty tree, performs no reset or push, and merges only with explicit `--merge-dev` on `dev`. Never push to `upstream` or merge it directly into production `main`.

Custom code is isolated in `lib/globalkeys.php` and `admin/inc/tab_globalkeys.php`; likely small integration conflicts are in `lib.php`, `index.php`, `admin/index.php`, `lib/db.php`, and `schema.sql`.
