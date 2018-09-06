<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <title>PHP WebShell Killer by Greatfar</title>
</head>
<body>
</body>
<?php
define("SELF",php_self());
error_reporting(E_ERROR);
ini_set('max_execution_time',20000);
ini_set('memory_limit','512M');
header("content-Type: text/html; charset=utf-8");

function php_self(){
  $php_self=substr($_SERVER['PHP_SELF'],strrpos($_SERVER['PHP_SELF'],'/')+1);
  return $php_self;
}

/**
 * 使用在代码中自定义的特征代码的方式查找
 * 正则匹配数组
 * 把webshell特征码写到该数组中，即可查找包含这些字符串的webshell
 * 如下方要查找的webshell包含base64_decode(base64_decode 或包含 YUhSMGNEb3ZMM0JvY0dGd2F 或包含 thinkapi=base64_decode 或包含 @e#html这些字符串
 */
$matches = array(
    '/base64_decode(base64_decode/i',
	'/YUhSMGNEb3ZMM0JvY0dGd2F/i',
    '/thinkapi=base64_decode/i',
	'/@e#html/i'
);

//如果用户输入了特征码，使用用户输入的特征代码片段的方式查找
if(isset($_POST['subcode']) && !empty($_POST['subcode'])) {
    $matches = array("/{$_POST['subcode']}/i");
}

/**
 * 查杀webshell主函数
 * @param  [type] $dir     查找目录
 * @param  [type] $exs     扩展名
 * @param  [type] $matches 正则表达式匹配数组,用于特征代码查找
 * @return [type]          返回值，查找完成返回true
 */
function antivirus($dir,$exs,$matches) {
    if(($handle = @opendir($dir)) == NULL) return false;
    while(false !== ($name = readdir($handle))) {
        if($name == '.' || $name == '..') continue;
        $path = $dir.$name;
        if(strstr($name,SELF)) continue;
        if(is_dir($path)) {
            if(is_readable($path)) antivirus($path.'/',$exs,$matches);
        }else {
            if(!preg_match($exs,$name)) continue;
            if(filesize($path) > 10000000) continue;
            $fp = fopen($path,'r');
            $code = fread($fp,filesize($path));
            fclose($fp);
            if(empty($code)) continue;
            foreach($matches as $matche) {
                $array = array();
                preg_match($matche,$code,$array);
                if(!$array) continue;
                if(strpos($array[0],"\x24\x74\x68\x69\x73\x2d\x3e")) continue;
                $len = strlen($array[0]);
                if($len > 6 && $len < 200) {
                    echo '特征 <input type="text" style="width:250px;" value="'.htmlspecialchars($array[0]).'">    '.$path.'<p></p>';
                    if(isset($_POST['isdel']) && $_POST['isdel'] =="true") {
                        unlink ($path);
                        echo "{$path}<span style='color:#f00;font-weight:bold;'>文件已删除</span><br><br>";
                    }
                    flush(); ob_flush(); break;
                }
            }
            unset($code,$array);
        }
    }
    closedir($handle);
    return true;
}
function strdir($str) { return str_replace(array('\\','//','//'),array('/','/','/'),chop($str)); }
echo '<form method="POST">';
echo '路径: <input type="text" name="dir" value="'.($_POST['dir'] ? strdir($_POST['dir'].'/') : strdir($_SERVER['DOCUMENT_ROOT'].'/')).'" style="width:398px;"><p></p>';
echo '后缀: <input type="text" name="exs" value="'.($_POST['exs'] ? $_POST['exs'] : '.php|.inc|.phtml').'" style="width:398px;"><p></p>';
echo '特征代码: <input type="text" name="subcode" value="'.($_POST['subcode'] ? $_POST['subcode'] : '').'" style="width:366px;"><p></p>';
echo '自动删除查找到的文件: <input type="checkbox" name="isdel" value="true"/><p></p>';
echo '操作: <input type="submit" style="width:80px;" value="扫描"><p></p>';
echo '</form>';
if(file_exists($_POST['dir']) && $_POST['exs']) {
    $dir = strdir($_POST['dir'].'/');
    $exs = '/('.str_replace('.','\\.',$_POST['exs']).')/i';
    echo antivirus($dir,$exs,$matches) ? '</br ><p></p>扫描完毕!' : '</br > <p></p>扫描中断';
}
?>
</html>
