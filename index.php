<?php
declare(strict_types=1);

$root = __DIR__;
$dataDir = $root . '/data';
foreach ([$dataDir, "$dataDir/cache", "$dataDir/history"] as $directory) {
    if (!is_dir($directory)) mkdir($directory, 0700, true);
}

ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', '1');
session_start();

function read_json(string $path, array $default = []): array {
    if (!is_file($path)) return $default;
    $json = json_decode((string) file_get_contents($path), true);
    return is_array($json) ? $json : $default;
}

function write_json(string $path, array $value): bool {
    $directory = dirname($path);
    if (!is_dir($directory)) mkdir($directory, 0700, true);
    $temporary = tempnam($directory, '.tmp');
    if ($temporary === false) return false;
    $json = json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if ($json === false || file_put_contents($temporary, $json, LOCK_EX) === false) return false;
    @chmod($temporary, 0600);
    return rename($temporary, $path);
}

function csrf_token(): string {
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf'];
}

function require_csrf(): void {
    $token = $_POST['csrf'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!hash_equals($_SESSION['csrf'] ?? '', (string) $token)) {
        http_response_code(403);
        exit('Invalid CSRF token');
    }
}

function h($value): string {
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

$usersFile = "$dataDir/users.json";
$settingsFile = "$dataDir/settings.json";
$sitesFile = "$dataDir/sites.json";
$users = read_json($usersFile);
$settings = read_json($settingsFile, [
    'telegram' => '', 'slack' => '', 'email' => '',
    'alerts' => ['down' => true, 'ssl' => true, 'admin' => true, 'permissions' => true, 'malware' => true]
]);
$sites = read_json($sitesFile);
$action = $_GET['action'] ?? '';

// First-run setup has priority. The callback can remain public and is not an admin action.
if ($action === 'verify') {
    header('Content-Type: application/json');
    $rawCallback = (string) file_get_contents('php://input');
    $body = json_decode($rawCallback, true);
    $nonce = is_array($body) ? (string) ($body['nonce'] ?? '') : '';
    $callbackTimestamp = is_array($body) ? (int) ($body['timestamp'] ?? 0) : 0;
    $nonceFile = "$dataDir/nonces.json";
    $record = read_json($nonceFile);
    $valid = strlen($nonce) >= 16 && abs(time() - $callbackTimestamp) <= 30;
    $siteId = (string) ($_GET['site_id'] ?? '');
    $matchingSite = null;
    foreach ($sites as $site) if (hash_equals((string) $site['id'], $siteId)) $matchingSite = $site;
    $signature = (string) ($_SERVER['HTTP_X_SIGNATURE'] ?? '');
    if ($matchingSite) {
        $expected = hash_hmac('sha256', $rawCallback, (string) $matchingSite['secret']);
        $valid = $valid && hash_equals($expected, $signature);
    } else {
        $valid = false;
    }
    if ($valid) {
        foreach ($record as $entry) if (hash_equals((string) $entry, $nonce)) $valid = false;
        if ($valid) {
            $record[] = $nonce;
            $record = array_slice(array_values(array_filter($record, function ($n) use ($now) {
                return strlen((string) $n) >= 16;
            })), -1000);
            write_json($nonceFile, $record);
        }
    }
    echo json_encode(['ok' => $valid, 'nonce' => $nonce]);
    exit;
}

if (!$users) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'setup') {
        require_csrf();
        $name = trim((string) ($_POST['name'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');
        if ($name === '' || strlen($password) < 8) $setupError = 'Name and a password of at least 8 characters are required.';
        else {
            $users = [['name' => $name, 'password' => password_hash($password, PASSWORD_DEFAULT), 'role' => 'Admin', 'created' => date('c')]];
            write_json($usersFile, $users);
            $_SESSION['user'] = $name;
            session_regenerate_id(true);
            header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
            exit;
        }
    }
} elseif (!isset($_SESSION['user'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'login') {
        require_csrf();
        $name = (string) ($_POST['name'] ?? '');
        $password = (string) ($_POST['password'] ?? '');
        foreach ($users as $user) {
            if (($user['name'] ?? '') === $name && password_verify($password, (string) ($user['password'] ?? ''))) {
                $_SESSION['user'] = $name;
                $_SESSION['role'] = $user['role'] ?? 'User';
                session_regenerate_id(true);
                header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
                exit;
            }
        }
        $loginError = 'Invalid username or password.';
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf();
}

function is_admin(): bool {
    return ($_SESSION['role'] ?? '') === 'Admin';
}

function signed_request(string $url, array $payload, string $secret, int $timeout = 12): array {
    $timestamp = time();
    $nonce = bin2hex(random_bytes(16));
    $body = json_encode(array_merge($payload, ['timestamp' => $timestamp, 'nonce' => $nonce]), JSON_UNESCAPED_SLASHES);
    $signature = hash_hmac('sha256', $timestamp . '.' . $nonce . '.' . $body, $secret);
    $context = stream_context_create(['http' => [
        'method' => 'POST', 'timeout' => $timeout,
        'header' => "Content-Type: application/json\r\nX-Signature: $signature\r\n",
        'content' => $body, 'ignore_errors' => true
    ], 'ssl' => ['verify_peer' => true, 'verify_peer_name' => true]]);
    $raw = @file_get_contents($url, false, $context);
    $json = is_string($raw) ? json_decode($raw, true) : null;
    return is_array($json) ? $json : ['ok' => false, 'error' => 'Invalid or unreachable client response'];
}

function safe_remote_url(string $url): bool {
    $parts = parse_url($url);
    if (!is_array($parts) || !isset($parts['scheme'], $parts['host']) || !in_array($parts['scheme'], ['http', 'https'], true)) return false;
    if (preg_match('/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/i', $parts['host'])) return false;
    $address = gethostbynamel($parts['host']);
    if (!$address) return true;
    foreach ($address as $ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) return false;
    }
    return true;
}

function append_history(string $dataDir, string $siteId, array $entries): void {
    if (!$entries) return;
    $path = "$dataDir/history/$siteId.json";
    $history = read_json($path);
    foreach ($entries as $entry) {
        $entry['timestamp'] ??= date('c');
        $history[] = $entry;
    }
    $history = array_slice($history, -5000);
    write_json($path, $history);
}

function diff_snapshots(string $dataDir, array $site, array $old, array $new): array {
    $entries = [];
    $categories = [
        'tech' => ['label' => 'Tech Stack', 'old' => $old['tech'] ?? [], 'new' => $new['tech'] ?? []],
        'plugins' => ['label' => 'Plugins', 'old' => $old['plugins'] ?? [], 'new' => $new['plugins'] ?? []],
        'users' => ['label' => 'Users', 'old' => $old['users'] ?? [], 'new' => $new['users'] ?? []],
        'posts' => ['label' => 'Posts', 'old' => $old['posts'] ?? [], 'new' => $new['posts'] ?? []],
    ];
    foreach ($categories as $key => $category) {
        $oldJson = json_encode($category['old']);
        $newJson = json_encode($category['new']);
        if ($oldJson !== $newJson) $entries[] = ['category' => $category['label'], 'message' => 'Detected changes in ' . $category['label']];
    }
    $oldFiles = $old['files'] ?? [];
    $newFiles = $new['files'] ?? [];
    if (json_encode($oldFiles) !== json_encode($newFiles)) {
        $entries[] = ['category' => 'Files & Integrity', 'message' => 'Directory or file integrity changed'];
    }
    if (!empty($site['settings']['audit_history'])) append_history($dataDir, (string) $site['id'], $entries);
    return $entries;
}

function notify(array $settings, string $subject, string $message): void {
    if (!empty($settings['telegram'])) {
        $parts = parse_url($settings['telegram']);
        if (($parts['scheme'] ?? '') === 'https') @file_get_contents($settings['telegram'] . (str_contains($settings['telegram'], '?') ? '&' : '?') . 'text=' . urlencode($subject . "\n" . $message));
    }
    if (!empty($settings['slack'])) {
        $context = stream_context_create(['http' => ['method' => 'POST', 'header' => "Content-Type: application/json\r\n", 'content' => json_encode(['text' => $subject . "\n" . $message]), 'ignore_errors' => true]]);
        @file_get_contents($settings['slack'], false, $context);
    }
    if (!empty($settings['email']) && function_exists('mail')) @mail($settings['email'], $subject, $message);
}

function client_script(string $secret, string $callbackUrl): string {
    $escapedSecret = var_export($secret, true);
    $escapedCallback = var_export($callbackUrl, true);
    return <<<'CLIENT'
<?php
declare(strict_types=1);

$secret = SECRET;
$callbackUrl = CALLBACK;
header('Content-Type: application/json');
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$raw = file_get_contents('php://input');
$request = json_decode($raw ?: '{}', true);
if (!is_array($request)) { http_response_code(400); exit(json_encode(['ok'=>false,'error'=>'Invalid JSON'])); }
$timestamp = (int) ($request['timestamp'] ?? 0);
$nonce = (string) ($request['nonce'] ?? '');
$signature = (string) ($_SERVER['HTTP_X_SIGNATURE'] ?? '');
if (abs(time() - $timestamp) > 30 || strlen($nonce) < 16 || !hash_equals(hash_hmac('sha256', $timestamp . '.' . $nonce . '.' . $raw, $secret), $signature)) {
    http_response_code(401); exit(json_encode(['ok'=>false,'error'=>'Invalid signed request']));
}

$callbackTimestamp=time();
$callbackBody = json_encode(['nonce'=>$nonce,'timestamp'=>$callbackTimestamp], JSON_UNESCAPED_SLASHES);
$callbackSignature = hash_hmac('sha256', $callbackBody, $secret);
$context = stream_context_create(['http'=>['method'=>'POST','timeout'=>8,'header'=>"Content-Type: application/json\r\nX-Signature: $callbackSignature\r\n",'content'=>$callbackBody,'ignore_errors'=>true]]);
$check = @file_get_contents($callbackUrl, false, $context);
$checkJson = is_string($check) ? json_decode($check,true) : null;
if (!is_array($checkJson) || ($checkJson['ok'] ?? false) !== true) { http_response_code(403); exit(json_encode(['ok'=>false,'error'=>'Master verification failed'])); }

$root = realpath(__DIR__);
$task = (string) ($request['task'] ?? 'check');

if ($task === 'update') {
    $script = (string) ($request['script'] ?? '');
    $checksum = (string) ($request['checksum'] ?? '');
    if (!hash_equals(hash('sha256', $script), $checksum) || strlen($script) < 20) {
        http_response_code(400); exit(json_encode(['ok'=>false,'error'=>'Invalid update payload']));
    }
    $target = __FILE__;
    $temporary = tempnam(sys_get_temp_dir(), 'client-update');
    if ($temporary===false||file_put_contents($temporary,$script,LOCK_EX)===false||!@chmod($temporary,0755)||!@rename($temporary,$target)) {
        http_response_code(500); exit(json_encode(['ok'=>false,'error'=>'Update failed']));
    }
    exit(json_encode(['ok'=>true,'updated'=>true]));
}

function safe_realpath($path, $root) {
    $real = realpath((string) $path);
    return $real !== false && ($real === $root || str_starts_with($real, rtrim($root,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR));
}

function cms_detect($root) {
    if (is_file("$root/wp-includes/version.php")) {
        $text=@file_get_contents("$root/wp-includes/version.php");
        if (preg_match('/\\$wp_version\\s*=\\s*[\'"]([^\'"]+)/',$text,$m)) return ['type'=>'WordPress','version'=>$m[1]];
    }
    if (is_file("$root/core/lib/Drupal.php")) return ['type'=>'Drupal','version'=>'Detected'];
    if (is_file("$root/version.php")) {
        $text=@file_get_contents("$root/version.php");
        if (strpos($text,'MOODLE')!==false) return ['type'=>'Moodle','version'=>'Detected'];
    }
    return ['type'=>'Generic PHP','version'=>PHP_VERSION];
}

function disk_values() {
    $total=(float)@disk_total_space(__DIR__);
    $free=(float)@disk_free_space(__DIR__);
    return ['total'=>round($total/1073741824,2),'used'=>round(($total-$free)/1073741824,2),'free'=>round($free/1073741824,2),'unit'=>'GB'];
}

$cms=cms_detect($root);
$headers=@getallheaders();
$serverSoftware=$_SERVER['SERVER_SOFTWARE'] ?? (($headers['Server']??'') ?: 'Unknown');
$tech=['cms'=>$cms['type'],'cms_version'=>$cms['version'],'server'=>$serverSoftware,'php'=>PHP_VERSION,'sapi'=>PHP_SAPI,
  'memory_limit'=>ini_get('memory_limit'),'max_execution_time'=>ini_get('max_execution_time'),'upload_max_filesize'=>ini_get('upload_max_filesize'),
  'extensions'=>array_values(array_intersect(get_loaded_extensions(),['curl','json','mysqli','pdo','pdo_mysql','openssl','gd','zip','mbstring']))];

$database=['engine'=>'Unknown','version'=>'','size_mb'=>0,'table_count'=>0];
if (is_file("$root/wp-config.php")) {
    $config=@file_get_contents("$root/wp-config.php");
    $values=[];
    foreach(['DB_NAME','DB_USER','DB_PASSWORD','DB_HOST'] as $key) if(preg_match('/define\\s*\\(\\s*[\'"]'.$key.'[\'"]\\s*,\\s*[\'"]([^\'"]*)[\'"]\\s*\\)/',$config,$m)) $values[$key]=$m[1];
    if(isset($values['DB_HOST'],$values['DB_NAME'],$values['DB_USER'])) {
        $mysqli=@mysqli_connect($values['DB_HOST'],$values['DB_USER'],$values['DB_PASSWORD']??'',$values['DB_NAME']);
        if($mysqli) {
            $v=@mysqli_get_server_info($mysqli);
            $database['engine']=stripos($v,'MariaDB')!==false?'MariaDB':'MySQL';
            $database['version']=$v;
            $escaped=mysqli_real_escape_string($mysqli,$values['DB_NAME']);
            $r=@mysqli_query($mysqli,"SELECT COUNT(*) AS c, ROUND(SUM(data_length+index_length)/1048576,2) AS mb FROM information_schema.tables WHERE table_schema='$escaped'");
            if($r && $row=mysqli_fetch_assoc($r)){ $database['table_count']=(int)$row['c']; $database['size_mb']=(float)$row['mb']; }
            mysqli_close($mysqli);
        }
    }
}
$cache=['checked_at'=>date('c'),'tech'=>array_merge($tech,['database'=>$database,'disk'=>disk_values(),'os'=>php_uname()])];

if ($task==='check'||$task==='tech'||$task==='full') $payload=['ok'=>true,'tech'=>$cache['tech'],'os'=>php_uname()];
elseif ($task==='files'||$task==='full') {
    $config=is_array($request['config']??null)?$request['config']:[];
    $exclusions=array_filter(array_map('trim',explode(',',(string)($config['folders']??''))));
    $extensions=array_filter(array_map('trim',explode(',',(string)($config['extensions']??''))));
    $files=[];$malware=[];$total=0;
    $iterator=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS));
    foreach($iterator as $file) {
        $path=$file->getRealPath(); if($path===false||!safe_realpath($path,$root)) continue;
        $relative=str_replace($root.DIRECTORY_SEPARATOR,'',$path);
        $skip=false;
        foreach($exclusions as $excluded) if($excluded!==''&&(str_starts_with($relative,$excluded)||str_contains($relative,DIRECTORY_SEPARATOR.$excluded))) $skip=true;
        if($skip||is_dir($path)) continue;
        $extension='.'.strtolower($file->getExtension()); if(in_array($extension,$extensions,true)) continue;
        $record=['path'=>$relative];
        if(!empty($config['size'])){$record['size']=$file->getSize();$total+=(int)$record['size'];}
        if(!empty($config['mtime']))$record['mtime']=@filemtime($path);
        if(!empty($config['permissions']))$record['permissions']=substr(sprintf('%o',@fileperms($path)),-4);
        if(!empty($config['checksums']))$record['sha256']=@hash_file('sha256',$path);
        $files[]=$record;
        if(!empty($config['malware'])) {
            $isUpload=str_contains(strtolower($relative),'wp-content/uploads/')||(str_contains(strtolower($relative),'uploads/')&&strtolower($extension)==='.php');
            if($isUpload&&strtolower($extension)==='.php')$malware[]=['path'=>$relative,'pattern'=>'PHP file inside upload directory'];
            if(in_array(strtolower($extension),['.php','.phtml','.phar'],true)){
                $text=@file_get_contents($path); foreach(['eval(base64_decode(','shell_exec(','gzinflate('] as $pattern) if($text!==false&&str_contains(strtolower($text),strtolower($pattern))) $malware[]=['path'=>$relative,'pattern'=>$pattern];
            }
        }
    }
    $payload=['ok'=>true,'files'=>$files,'total_size'=>$total,'malware'=>$malware];
} elseif ($task==='plugins'||$task==='users'||$task==='posts'||$task==='full') {
    $payload=['ok'=>true];
    if(is_file("$root/wp-load.php")) {
        define('WP_USE_THEMES',false);
        require_once "$root/wp-load.php";
    }
    $payload['plugins']=[];$payload['users']=[];$payload['posts']=[];
    if(function_exists('get_plugins')) {
        foreach(get_plugins() as $path=>$plugin) {
            $status=is_plugin_active($path)?'Active':'Inactive';
            $payload['plugins'][]=['name'=>$plugin['Name']??$path,'version'=>$plugin['Version']??'','status'=>$status,'path'=>$path];
        }
    }
    if(function_exists('get_users')) {
        foreach(get_users(['orderby'=>'registered','order'=>'ASC']) as $user) {
            $payload['users'][]=['id'=>$user->ID,'name'=>$user->user_login,'email'=>$user->user_email,'roles'=>$user->roles,'registered'=>$user->user_registered];
        }
    }
    if(function_exists('get_posts')) {
        $today=wp_date('Y-m-d');
        $posts=get_posts(['post_type'=>'post','post_status'=>'any','numberposts'=>-1,'orderby'=>'date','order'=>'DESC']);
        foreach($posts as $post) {$payload['posts'][]=['id'=>$post->ID,'title'=>$post->post_title,'date'=>$post->post_date,'created_today'=>str_starts_with($post->post_date,$today)];}
    }
} elseif ($task==='error_log') {
    $candidates=["$root/error_log","$root/wp-content/debug.log"];
    $text='';foreach($candidates as $candidate){$real=realpath($candidate);if($real!==false&&safe_realpath($real,$root)){if(is_readable($real)){$lines=@file($real,FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES);if(is_array($lines))$text=implode("\n",array_slice($lines,-100));}}}
    $payload=['ok'=>true,'lines'=>$text];
} else $payload=['ok'=>false,'error'=>'Unknown task'];

echo json_encode($payload,JSON_UNESCAPED_SLASHES);
CLIENT;
}

if (isset($_SESSION['user']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $postAction = (string) ($_POST['action'] ?? '');

    if ($postAction === 'add_site') {
        $name = trim((string) ($_POST['name'] ?? ''));
        $baseUrl = rtrim(trim((string) ($_POST['base_url'] ?? '')), '/');
        if ($name === '' || !safe_remote_url($baseUrl)) {
            $flash = 'A valid public HTTP(S) site URL and name are required.';
        } elseif (is_admin()) {
            $id = bin2hex(random_bytes(12));
            $filename = 'client_' . bin2hex(random_bytes(4)) . '.php';
            $secret = bin2hex(random_bytes(32));
            $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
            $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
            $callback = $scheme . '://' . $host . dirname($_SERVER['SCRIPT_NAME']) . '/index.php?action=verify&site_id=' . urlencode($id);
            $site = [
                'id' => $id, 'name' => $name, 'base_url' => $baseUrl,
                'filename' => $filename, 'client_url' => $baseUrl . '/' . $filename,
                'secret' => $secret, 'callback_url' => $callback,
                'tags' => array_values(array_filter(array_map('trim', explode(',', (string) ($_POST['tags'] ?? ''))))),
                'notes' => trim((string) ($_POST['notes'] ?? '')),
                'status' => 'Offline', 'created_at' => date('c'), 'settings' => [
                    'folders' => '', 'extensions' => '.log,.tmp,.zip,.mp4',
                    'size' => true, 'mtime' => true, 'permissions' => true, 'checksums' => true,
                    'malware' => true, 'audit_history' => true, 'cms_override' => ''
                ],
                'cron' => []
            ];
            $sites[] = $site;
            write_json($sitesFile, $sites);
            write_json("$dataDir/cache/$id.json", ['checked_at' => null, 'tech' => [], 'files' => [], 'plugins' => [], 'users' => [], 'posts' => []]);
            $flash = 'Site registered. Download the generated client and upload it to the target root.';
        } else {
            $flash = 'Administrator permission required.';
        }
    }

    if ($postAction === 'save_settings') {
        $settings = [
            'telegram' => trim((string) ($_POST['telegram'] ?? '')),
            'slack' => trim((string) ($_POST['slack'] ?? '')),
            'email' => trim((string) ($_POST['email'] ?? '')),
            'alerts' => [
                'down' => isset($_POST['alert_down']), 'ssl' => isset($_POST['alert_ssl']),
                'admin' => isset($_POST['alert_admin']), 'permissions' => isset($_POST['alert_permissions']),
                'malware' => isset($_POST['alert_malware'])
            ]
        ];
        write_json($settingsFile, $settings);
        $flash = 'Global settings saved.';
    }

    if ($postAction === 'save_site') {
        $id = (string) ($_POST['site_id'] ?? '');
        foreach ($sites as &$site) if (hash_equals((string) $site['id'], $id)) {
            $site['name'] = trim((string) ($_POST['name'] ?? $site['name']));
            $site['tags'] = array_values(array_filter(array_map('trim', explode(',', (string) ($_POST['tags'] ?? '')))));
            $site['notes'] = trim((string) ($_POST['notes'] ?? ''));
            $site['settings'] = array_merge($site['settings'] ?? [], [
                'folders' => trim((string) ($_POST['folders'] ?? '')),
                'extensions' => trim((string) ($_POST['extensions'] ?? '')),
                'size' => isset($_POST['size']), 'mtime' => isset($_POST['mtime']),
                'permissions' => isset($_POST['permissions']), 'checksums' => isset($_POST['checksums']),
                'malware' => isset($_POST['malware']), 'audit_history' => isset($_POST['audit_history']),
                'cms_override' => trim((string) ($_POST['cms_override'] ?? ''))
            ]);
            $tasks = ['uptime','tech','files','plugins','users','posts'];
            foreach ($tasks as $task) {
                $enabled = isset($_POST["cron_$task"]);
                $existing = $site['cron'][$task] ?? ['last_run' => 0];
                $existing['enabled'] = $enabled;
                $existing['frequency'] = (string) ($_POST["frequency_$task"] ?? '60');
                $site['cron'][$task] = $existing;
            }
        }
        unset($site);
        write_json($sitesFile, $sites);
        $flash = 'Site settings and cron schedule saved.';
    }

    if ($postAction === 'add_user' && is_admin()) {
        $name = trim((string) ($_POST['name'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');
        $role = ($_POST['role'] ?? '') === 'Admin' ? 'Admin' : 'User';
        if ($name !== '' && strlen($password) >= 8) {
            $duplicate = false;
            foreach ($users as $user) if (($user['name'] ?? '') === $name) $duplicate = true;
            if (!$duplicate) {
                $users[] = ['name' => $name, 'password' => password_hash($password, PASSWORD_DEFAULT), 'role' => $role, 'created' => date('c')];
                write_json($usersFile, $users);
                $flash = 'User created.';
            } else $flash = 'That username already exists.';
        } else $flash = 'User name and password of at least 8 characters are required.';
    }

    if ($postAction === 'logout') {
        $_SESSION = [];
        session_destroy();
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
        exit;
    }

    if (($postAction === 'sync' || $postAction === 'check') && isset($_POST['site_id'])) {
        $id = (string) $_POST['site_id'];
        foreach ($sites as &$site) if (hash_equals((string) $site['id'], $id)) {
            $task = $postAction === 'check' ? 'check' : 'full';
            $payload = signed_request((string) $site['client_url'], [
                'task' => $task, 'config' => $site['settings'] ?? []
            ], (string) $site['secret']);
            if (!empty($payload['ok'])) {
                $old = read_json("$dataDir/cache/$id.json");
                $site['status'] = 'Online';
                $site['last_sync'] = date('c');
                $cache = [
                    'checked_at' => date('c'), 'tech' => $payload['tech'] ?? ($old['tech'] ?? []),
                    'files' => $payload['files'] ?? ($old['files'] ?? []),
                    'plugins' => $payload['plugins'] ?? ($old['plugins'] ?? []),
                    'users' => $payload['users'] ?? ($old['users'] ?? []),
                    'posts' => $payload['posts'] ?? ($old['posts'] ?? []),
                    'malware' => $payload['malware'] ?? []
                ];
                write_json("$dataDir/cache/$id.json", $cache);
                diff_snapshots($dataDir, $site, $old, $cache);
            } else {
                $site['status'] = 'Offline';
                $flash = 'Connection failed: ' . ($payload['error'] ?? 'Unknown error');
            }
        }
        unset($site);
        write_json($sitesFile, $sites);
        if (!isset($flash)) $flash = 'Live sync completed.';
    }

    if ($postAction === 'push_update') {
        $targets = ($_POST['bulk'] ?? '') === '1'
            ? $sites
            : array_values(array_filter($sites, fn($s) => hash_equals((string) $s['id'], (string) ($_POST['site_id'] ?? ''))));
        foreach ($targets as $target) {
            $script = client_script((string) $target['secret'], (string) $target['callback_url']);
            $script = str_replace("<?php\n", "<?php\n", $script);
            $script = str_replace('$secret = SECRET;', '$secret = ' . var_export((string) $target['secret'], true) . ';', $script);
            $script = str_replace('$callbackUrl = CALLBACK;', '$callbackUrl = ' . var_export((string) $target['callback_url'], true) . ';', $script);
            signed_request((string) $target['client_url'], ['task' => 'update', 'script' => $script, 'checksum' => hash('sha256', $script)], (string) $target['secret']);
        }
        $flash = 'Client update payload dispatched.';
    }

    if ($postAction === 'fetch_error_log') {
        $id = (string) ($_POST['site_id'] ?? '');
        foreach ($sites as &$site) if (hash_equals((string) $site['id'], $id)) {
            $payload = signed_request((string) $site['client_url'], ['task' => 'error_log'], (string) $site['secret']);
            if (!empty($payload['ok'])) {
                $cache = read_json("$dataDir/cache/$id.json");
                $cache['error_log'] = (string) ($payload['lines'] ?? '');
                write_json("$dataDir/cache/$id.json", $cache);
                $flash = 'PHP error log refreshed.';
            } else $flash = 'Could not fetch PHP error log.';
        }
        unset($site);
    }
}

// Download a generated standalone client.
if (isset($_SESSION['user']) && ($action === 'download')) {
    $id = (string) ($_GET['site'] ?? '');
    foreach ($sites as $site) if (hash_equals((string) $site['id'], $id)) {
        $script = client_script((string) $site['secret'], (string) $site['callback_url']);
        $script = str_replace('$secret = SECRET;', '$secret = ' . var_export((string) $site['secret'], true) . ';', $script);
        $script = str_replace('$callbackUrl = CALLBACK;', '$callbackUrl = ' . var_export((string) $site['callback_url'], true) . ';', $script);
        header('Content-Type: application/x-httpd-php');
        header('Content-Disposition: attachment; filename="' . $site['filename'] . '"');
        echo $script;
        exit;
    }
}

if (isset($_SESSION['user']) && $action === 'report') {
    $id = (string) ($_GET['site'] ?? '');
    foreach ($sites as $site) if (hash_equals((string) $site['id'], $id)) {
        $cache = read_json("$dataDir/cache/$id.json");
        $history = read_json("$dataDir/history/$id.json");
        echo '<!doctype html><html><head><meta charset="utf-8"><title>Maintenance Report</title><style>body{font-family:Arial;margin:40px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:8px} @media print{button{display:none}}</style></head><body>';
        echo '<button onclick="print()">Print / Export PDF</button><h1>' . h($site['name']) . ' Maintenance Report</h1>';
        echo '<p>Generated ' . h(date('c')) . ' | Status: ' . h($site['status']) . '</p>';
        echo '<h2>Technology Stack</h2><pre>' . h(json_encode($cache['tech'] ?? [], JSON_PRETTY_PRINT)) . '</pre>';
        echo '<h2>Plugins</h2><table><tr><th>Name</th><th>Version</th><th>Status</th></tr>';
        foreach ($cache['plugins'] ?? [] as $plugin) echo '<tr><td>' . h($plugin['name'] ?? '') . '</td><td>' . h($plugin['version'] ?? '') . '</td><td>' . h($plugin['status'] ?? '') . '</td></tr>';
        echo '</table><h2>Recent Changes</h2><ul>';
        foreach (array_slice(array_reverse($history), 0, 20) as $entry) echo '<li>' . h($entry['timestamp'] ?? '') . ' — ' . h($entry['category'] ?? '') . ': ' . h($entry['message'] ?? '') . '</li>';
        echo '</ul></body></html>';
        exit;
    }
}

?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>PHP Fleet Manager</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-100 text-slate-900">
<?php if (!$users): ?>
<main class="min-h-screen flex items-center justify-center p-6">
  <form method="post" class="w-full max-w-md rounded-xl bg-white p-8 shadow">
    <input type="hidden" name="csrf" value="<?=h(csrf_token())?>">
    <input type="hidden" name="action" value="setup">
    <h1 class="mb-2 text-2xl font-bold">Initial Admin Setup</h1>
    <p class="mb-6 text-sm text-slate-600">Create the first account. It will become the administrator.</p>
    <?php if(!empty($setupError)):?><p class="mb-4 rounded bg-red-100 p-3 text-red-700"><?=h($setupError)?></p><?php endif;?>
    <label class="block text-sm font-medium">Admin name<input name="name" required class="mt-1 w-full rounded border p-2"></label>
    <label class="mt-4 block text-sm font-medium">Password<input name="password" type="password" minlength="8" required class="mt-1 w-full rounded border p-2"></label>
    <button class="mt-6 w-full rounded bg-blue-600 p-2 font-semibold text-white">Create Admin</button>
  </form>
</main>
<?php elseif (!isset($_SESSION['user'])): ?>
<main class="min-h-screen flex items-center justify-center p-6">
  <form method="post" class="w-full max-w-md rounded-xl bg-white p-8 shadow">
    <input type="hidden" name="csrf" value="<?=h(csrf_token())?>">
    <input type="hidden" name="action" value="login">
    <h1 class="mb-6 text-2xl font-bold">Fleet Manager Login</h1>
    <?php if(!empty($loginError)):?><p class="mb-4 rounded bg-red-100 p-3 text-red-700"><?=h($loginError)?></p><?php endif;?>
    <label class="block text-sm font-medium">Username<input name="name" required class="mt-1 w-full rounded border p-2"></label>
    <label class="mt-4 block text-sm font-medium">Password<input name="password" type="password" required class="mt-1 w-full rounded border p-2"></label>
    <button class="mt-6 w-full rounded bg-blue-600 p-2 font-semibold text-white">Sign in</button>
  </form>
</main>
<?php else: ?>
<header class="border-b bg-slate-950 px-6 py-4 text-white">
  <div class="mx-auto flex max-w-7xl items-center justify-between">
    <h1 class="text-xl font-bold">PHP Fleet Manager</h1>
    <div class="flex items-center gap-4 text-sm"><span><?=h($_SESSION['user'])?> · <?=h($_SESSION['role'] ?? 'User')?></span>
      <form method="post"><input type="hidden" name="csrf" value="<?=h(csrf_token())?>"><input type="hidden" name="action" value="logout"><button class="rounded border px-3 py-1">Logout</button></form>
    </div>
  </div>
</header>
<main class="mx-auto max-w-7xl p-6">
<?php if(!empty($flash)):?><div class="mb-4 rounded border border-blue-200 bg-blue-50 p-3 text-blue-800"><?=h($flash)?></div><?php endif;?>

<form class="mb-6 flex gap-2" method="get">
  <input name="q" value="<?=h($_GET['q']??'')?>" placeholder="Search filename, plugin, PHP version, username…" class="w-full rounded border bg-white p-3">
  <button class="rounded bg-slate-800 px-5 text-white">Search</button>
</form>

<?php
$query=strtolower(trim((string)($_GET['q']??'')));
if($query!=='') {
 echo '<section class="mb-6 rounded bg-white p-4 shadow"><h2 class="mb-3 font-bold">Global Search</h2>';
 foreach($sites as $site) {
  $cache=read_json("$dataDir/cache/".$site['id'].".json");
  $haystack=strtolower(json_encode($cache));
  if(str_contains($haystack,$query)) echo '<div class="border-b py-2"><strong>'.h($site['name']).'</strong> <span class="text-sm text-slate-500">matched cached snapshot</span></div>';
 }
 echo '</section>';
}
?>

<section class="mb-6 overflow-hidden rounded bg-white shadow">
  <div class="flex items-center justify-between border-b p-4"><h2 class="font-bold">Fleet Overview</h2>
    <?php if(is_admin()):?><button onclick="document.getElementById('add-site').showModal()" type="button" class="rounded bg-blue-600 px-3 py-2 text-sm font-semibold text-white">Add Website</button><?php endif;?>
  </div>
  <div class="overflow-x-auto"><table class="w-full text-left text-sm">
    <thead class="bg-slate-50 text-xs uppercase text-slate-500"><tr><th class="p-3">Site</th><th class="p-3">Status</th><th class="p-3">CMS / PHP</th><th class="p-3">Server / DB</th><th class="p-3">Disk</th><th class="p-3">Last Sync</th><th class="p-3">Actions</th></tr></thead>
    <tbody>
    <?php foreach($sites as $site):
      $cache=read_json("$dataDir/cache/".$site['id'].".json");$tech=$cache['tech']??[];$disk=$tech['disk']??[];$db=$tech['database']??[];
    ?>
      <tr class="border-t">
        <td class="p-3"><div class="font-semibold"><?=h($site['name'])?></div><div class="text-xs text-slate-500"><?=h($site['base_url'])?></div><?php foreach($site['tags']??[] as $tag):?><span class="mr-1 rounded bg-slate-100 px-1 text-xs"><?=h($tag)?></span><?php endforeach;?></td>
        <td class="p-3"><span class="rounded px-2 py-1 <?=($site['status']??'Offline')==='Online'?'bg-green-100 text-green-700':'bg-red-100 text-red-700'?>"><?=h($site['status']??'Offline')?></span></td>
        <td class="p-3"><?=h(($tech['cms']??($site['settings']['cms_override']??'Unknown')).' '.($tech['cms_version']??''))?><br><span class="text-xs text-slate-500">PHP <?=h($tech['php']??'Unknown')?></span></td>
        <td class="p-3"><?=h($tech['server']??'Unknown')?><br><span class="text-xs text-slate-500"><?=h(($db['engine']??'DB').' '.($db['version']??''))?></span></td>
        <td class="p-3"><?=h(($disk['used']??'?').' / '.($disk['total']??'?').' '.($disk['unit']??'GB'))?></td>
        <td class="p-3"><?=h($site['last_sync']??'Never')?></td>
        <td class="p-3">
          <form method="post" class="flex flex-wrap gap-1"><input type="hidden" name="csrf" value="<?=h(csrf_token())?>"><input type="hidden" name="site_id" value="<?=h($site['id'])?>">
            <button name="action" value="sync" class="rounded border px-2 py-1">Sync</button>
            <button name="action" value="check" class="rounded border px-2 py-1">Check</button>
            <a class="rounded border px-2 py-1" href="?action=download&site=<?=urlencode($site['id'])?>">Client</a>
            <a class="rounded border px-2 py-1" target="_blank" href="?action=report&site=<?=urlencode($site['id'])?>">Report</a>
          </form>
        </td>
      </tr>
    <?php endforeach;?>
    </tbody>
  </table></div>
</section>

<?php if(is_admin()):?>
<dialog id="add-site" class="w-full max-w-lg rounded p-0">
  <form method="post" class="p-6"><input type="hidden" name="csrf" value="<?=h(csrf_token())?>"><input type="hidden" name="action" value="add_site">
    <h2 class="mb-4 text-xl font-bold">Register Website</h2>
    <label class="block text-sm">Site Name<input name="name" required class="mt-1 w-full rounded border p-2"></label>
    <label class="mt-3 block text-sm">Base URL<input name="base_url" type="url" required placeholder="https://example.com" class="mt-1 w-full rounded border p-2"></label>
    <label class="mt-3 block text-sm">Tags / Groups<input name="tags" placeholder="Production, Client Name" class="mt-1 w-full rounded border p-2"></label>
    <label class="mt-3 block text-sm">Notes<textarea name="notes" class="mt-1 w-full rounded border p-2"></textarea></label>
    <div class="mt-5 flex justify-end gap-2"><button type="button" onclick="this.closest('dialog').close()" class="rounded border px-4 py-2">Cancel</button><button class="rounded bg-blue-600 px-4 py-2 text-white">Generate Client</button></div>
  </form>
</dialog>
<?php endif;?>

<div class="grid gap-6 md:grid-cols-2">
  <?php if(is_admin()):?>
  <section class="rounded bg-white p-5 shadow"><h2 class="mb-4 font-bold">Global Alert Settings</h2>
    <form method="post"><input type="hidden" name="csrf" value="<?=h(csrf_token())?>"><input type="hidden" name="action" value="save_settings">
      <label class="block text-sm">Telegram Bot API URL / Webhook<input name="telegram" value="<?=h($settings['telegram']??'')?>" class="mt-1 w-full rounded border p-2"></label>
      <label class="mt-3 block text-sm">Slack / Discord Webhook<input name="slack" value="<?=h($settings['slack']??'')?>" class="mt-1 w-full rounded border p-2"></label>
      <label class="mt-3 block text-sm">Alert Email<input name="email" type="email" value="<?=h($settings['email']??'')?>" class="mt-1 w-full rounded border p-2"></label>
      <div class="mt-3 grid grid-cols-2 gap-2 text-sm">
        <?php foreach(['down'=>'Down / back up','ssl'=>'SSL < 14 days','admin'=>'New WordPress admin','permissions'=>'0777 permissions','malware'=>'Rogue PHP / malware'] as $key=>$label):?><label><input type="checkbox" name="alert_<?=$key?>" <?=!empty($settings['alerts'][$key])?'checked':''?>> <?=$label?></label><?php endforeach;?>
      </div><button class="mt-4 rounded bg-slate-800 px-4 py-2 text-white">Save Settings</button>
    </form>
  </section>
  <section class="rounded bg-white p-5 shadow"><h2 class="mb-4 font-bold">User Management</h2>
    <ul class="mb-4 text-sm"><?php foreach($users as $user):?><li class="border-b py-2"><?=h($user['name'])?> — <?=h($user['role'])?></li><?php endforeach;?></ul>
    <form method="post"><input type="hidden" name="csrf" value="<?=h(csrf_token())?>"><input type="hidden" name="action" value="add_user">
      <div class="grid grid-cols-2 gap-2"><input name="name" required placeholder="Username" class="rounded border p-2"><input name="password" type="password" minlength="8" required placeholder="Password" class="rounded border p-2"></div>
      <select name="role" class="mt-2 rounded border p-2"><option>User</option><option>Admin</option></select><button class="ml-2 rounded bg-slate-800 px-4 py-2 text-white">Add User</button>
    </form>
  </section>
  <?php endif;?>
</div>

<?php foreach($sites as $site):?>
<details class="mt-6 rounded bg-white shadow">
  <summary class="cursor-pointer p-4 font-bold"><?=h($site['name'])?> — Settings & Cron</summary>
  <form method="post" class="border-t p-5"><input type="hidden" name="csrf" value="<?=h(csrf_token())?>"><input type="hidden" name="action" value="save_site"><input type="hidden" name="site_id" value="<?=h($site['id'])?>">
    <div class="grid gap-3 md:grid-cols-2">
      <label class="text-sm">Site Name<input name="name" value="<?=h($site['name'])?>" class="mt-1 w-full rounded border p-2"></label>
      <label class="text-sm">Tags<input name="tags" value="<?=h(implode(', ', $site['tags']??[]))?>" class="mt-1 w-full rounded border p-2"></label>
      <label class="text-sm md:col-span-2">Notes<textarea name="notes" class="mt-1 w-full rounded border p-2"><?=h($site['notes']??'')?></textarea></label>
    </div>
    <h3 class="mt-5 font-bold">Scanner Configuration</h3>
    <div class="mt-2 grid gap-3 md:grid-cols-2">
      <label class="text-sm">Excluded folders<input name="folders" value="<?=h($site['settings']['folders']??'')?>" placeholder="node_modules, .git, vendor" class="mt-1 w-full rounded border p-2"></label>
      <label class="text-sm">Ignored extensions<input name="extensions" value="<?=h($site['settings']['extensions']??'')?>" placeholder=".log,.tmp,.zip" class="mt-1 w-full rounded border p-2"></label>
    </div>
    <div class="mt-3 grid grid-cols-2 gap-2 text-sm md:grid-cols-3">
      <?php foreach(['size'=>'Get file size','mtime'=>'Get modified date','permissions'=>'Get permissions','checksums'=>'SHA-256 checksums','malware'=>'Malware / rogue scan','audit_history'=>'Change history'] as $key=>$label):?><label><input type="checkbox" name="<?=$key?>" <?=!empty($site['settings'][$key])?'checked':''?>> <?=$label?></label><?php endforeach;?>
    </div>
    <label class="mt-3 block text-sm">Manual CMS / Software Override<select name="cms_override" class="mt-1 rounded border p-2"><option value="">Auto-detect</option><?php foreach(['WordPress','Moodle','Drupal','Generic PHP','Custom'] as $cms):?><option <?=$cms===($site['settings']['cms_override']??'')?'selected':''?>><?=$cms?></option><?php endforeach;?></select></label>
    <h3 class="mt-5 font-bold">Cron Schedule</h3>
    <div class="mt-2 space-y-2 text-sm">
      <?php foreach(['uptime'=>'Uptime & SSL','tech'=>'Tech & security posture','files'=>'Integrity scan','plugins'=>'WordPress plugins','users'=>'WordPress users','posts'=>'WordPress posts'] as $task=>$label):
        $schedule=$site['cron'][$task]??['enabled'=>false,'frequency'=>'60'];
      ?><label class="flex items-center gap-2"><input type="checkbox" name="cron_<?=$task?>" <?=$schedule['enabled']?'checked':''?>> <span class="w-48"><?=$label?></span><select name="frequency_<?=$task?>" class="rounded border p-1"><?php foreach(['5'=>'Every 5 minutes','30'=>'Every 30 minutes','60'=>'Every 60 minutes','360'=>'Every 6 hours','daily'=>'Daily'] as $value=>$text):?><option value="<?=$value?>" <?=$schedule['frequency']===$value?'selected':''?>><?=$text?></option><?php endforeach;?></select></label><?php endforeach;?>
    </div>
    <div class="mt-5 flex gap-2"><button class="rounded bg-blue-600 px-4 py-2 text-white">Save</button>
      <button type="submit" name="action" value="push_update" class="rounded border px-4 py-2">Push Client Update</button>
    </div>
  </form>
  <?php $cache=read_json("$dataDir/cache/".$site['id'].".json"); $history=read_json("$dataDir/history/".$site['id'].".json"); ?>
  <div class="grid gap-4 border-t p-5 md:grid-cols-2">
    <section><h3 class="font-bold">Overview &amp; Tech Stack</h3><pre class="mt-2 max-h-64 overflow-auto rounded bg-slate-50 p-3 text-xs"><?=h(json_encode($cache['tech']??[],JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES))?></pre></section>
    <section><h3 class="font-bold">Directory Tree &amp; Integrity</h3><div class="mt-2 max-h-64 overflow-auto text-xs"><?php foreach(array_slice($cache['files']??[],0,200) as $file):?><div class="border-b py-1"><?=h($file['path']??'')?> <?=h(isset($file['permissions'])?'· '.$file['permissions']:'')?> <?=h(isset($file['sha256'])?'· '.substr($file['sha256'],0,12):'')?></div><?php endforeach;?></div></section>
    <section><h3 class="font-bold">WordPress Users</h3><div class="mt-2 text-xs"><?php foreach($cache['users']??[] as $user):?><div class="border-b py-1"><?=h($user['name']??'')?> · <?=h(implode(', ',(array)($user['roles']??[])))?></div><?php endforeach;?></div></section>
    <section><h3 class="font-bold">Plugins</h3><div class="mt-2 text-xs"><?php foreach($cache['plugins']??[] as $plugin):?><div class="border-b py-1"><?=h($plugin['name']??'')?> <?=h($plugin['version']??'')?> · <?=h($plugin['status']??'')?></div><?php endforeach;?></div></section>
    <section><h3 class="font-bold">Posts</h3><div class="mt-2 max-h-40 overflow-auto text-xs"><?php foreach($cache['posts']??[] as $post):?><div class="border-b py-1"><?=h($post['title']??'')?> <?=!empty($post['created_today'])?'· created today':''?></div><?php endforeach;?></div></section>
    <section><h3 class="font-bold">SSL &amp; Security Audit</h3><pre class="mt-2 text-xs"><?=h(json_encode(['malware'=>$cache['malware']??[],'ssl'=>$cache['ssl']??null,'uptime'=>$cache['uptime']??null],JSON_PRETTY_PRINT))?></pre></section>
    <section class="md:col-span-2"><h3 class="font-bold">PHP Error Log</h3>
      <form method="post" class="mt-2"><input type="hidden" name="csrf" value="<?=h(csrf_token())?>"><input type="hidden" name="action" value="fetch_error_log"><input type="hidden" name="site_id" value="<?=h($site['id'])?>"><button class="rounded border px-3 py-1 text-xs">Fetch Last 100 Lines</button></form>
      <pre class="mt-2 max-h-64 overflow-auto rounded bg-slate-950 p-3 text-xs text-slate-100"><?=h($cache['error_log']??'No cached error log')?></pre>
    </section>
    <section class="md:col-span-2"><h3 class="font-bold">History / Audit Log</h3><div class="mt-2 max-h-64 overflow-auto text-xs"><?php foreach(array_slice(array_reverse($history),0,200) as $entry):?><div class="border-b py-2"><b><?=h($entry['timestamp']??'')?></b> · <?=h($entry['category']??'')?> — <?=h($entry['message']??'')?></div><?php endforeach;?></div></section>
  </div>
</details>
<?php endforeach;?>
</main>
<?php endif;?>
</body>
</html>
