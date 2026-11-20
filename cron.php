<?php
declare(strict_types=1);
$root=__DIR__;$data="$root/data";
$secret=getenv('CRON_SECRET')?:'';
$provided=$_GET['token']??($_SERVER['HTTP_X_CRON_TOKEN']??'');
if($secret!==''&&(!is_string($provided)||!hash_equals($secret,$provided))) { http_response_code(403); exit('Forbidden');}
function jread($p,$d=[]){return is_file($p)?(json_decode(file_get_contents($p),true)?:$d):$d;}
function jwrite($p,$v){$t=tempnam(dirname($p),'.tmp');file_put_contents($t,json_encode($v,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));return rename($t,$p);}
$sites=jread("$data/sites.json");$settings=jread("$data/settings.json");$now=time();
foreach($sites as &$site){
 $schedules=$site['cron']??[];
 foreach($schedules as $task=>$schedule){
  if(empty($schedule['enabled']))continue;
  $minutes=['5'=>5,'30'=>30,'60'=>60,'360'=>360,'daily'=>1440];
  $interval=$minutes[(string)($schedule['frequency']??'60')]??60;
  $last=(int)($schedule['last_run']??0);
  if($now-$last<$interval*60)continue;
  $payload=['task'=>$task,'timestamp'=>$now,'nonce'=>bin2hex(random_bytes(16))];
  $body=json_encode($payload,JSON_UNESCAPED_SLASHES);
  $signature=hash_hmac('sha256',$now.'.'.$payload['nonce'].'.'.$body,(string)$site['secret']);
  $context=stream_context_create(['http'=>['method'=>'POST','timeout'=>15,'header'=>"Content-Type: application/json\r\nX-Signature: $signature\r\n",'content'=>$body,'ignore_errors'=>true]]);
  $raw=@file_get_contents((string)$site['client_url'],false,$context);
  $schedule['last_run']=$now;$schedule['last_status']=is_string($raw)?'Sent':'Failed';$schedules[$task]=$schedule;
  if(is_string($raw)){$decoded=json_decode($raw,true);if(is_array($decoded)){$cache=jread("$data/cache/".$site['id'].".json");$cache[$task]=$decoded;jwrite("$data/cache/".$site['id'].".json",$cache);}}
 }
 $site['cron']=$schedules;
}
unset($site);jwrite("$data/sites.json",$sites);
echo json_encode(['ok'=>true,'ran'=>count($sites),'timestamp'=>date('c')]);
