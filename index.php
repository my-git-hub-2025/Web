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
    $body = json_decode((string) file_get_contents('php://input'), true);
    $nonce = is_array($body) ? (string) ($body['nonce'] ?? '') : '';
    $nonceFile = "$dataDir/nonces.json";
    $record = read_json($nonceFile);
    $valid = strlen($nonce) >= 16;
    $siteId = (string) ($_GET['site_id'] ?? '');
    $matchingSite = null;
    foreach ($sites as $site) if (hash_equals((string) $site['id'], $siteId)) $matchingSite = $site;
    $signature = (string) ($_SERVER['HTTP_X_SIGNATURE'] ?? '');
    if ($matchingSite) {
        $expected = hash_hmac('sha256', (string) file_get_contents('php://input'), (string) $matchingSite['secret']);
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

$callbackBody = json_encode(['nonce'=>$nonce], JSON_UNESCAPED_SLASHES);
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
