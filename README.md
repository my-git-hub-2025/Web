# PHP Website Manager

A flat-file, session-authenticated PHP fleet dashboard.

## Run

```bash
php -S 127.0.0.1:8080
```

Open `http://127.0.0.1:8080/index.php` and complete the initial administrator setup.
The optional CLI/web cron runner is `cron.php`; protect HTTP access with `CRON_SECRET`:

```bash
CRON_SECRET='replace-me' php -S 127.0.0.1:8080
# Then: curl 'http://127.0.0.1:8080/cron.php?token=replace-me'
```