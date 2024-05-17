<?php

$shellCode = 'error_reporting'; // 特征码，webshell包含的代码，可以作为特征码：error_reporting eval base64_decode fwrite file_put_contents
$scanDir = '/data/www'; // 扫描目录
$fileExt = ['php', 'html', 'py']; // 扫描的文件扩展名

/**
 * webshell扫描器（基于特征代码）
 * 命令行模式运行，上传到服务器，执行 php scan.php 即可
 * @author Greatfar
 */
class ScanWebshell
{
    public static $matcheFileList = []; // 扫描命中的文件列表
    // 存在大量自动复制的webshell时，打开自动删除，非常有用
    public static $isLog = true; // 是否记录日志
    public static $isBak = true; // 备份被删除的文件
    public static $isDelFile = false; // 自动删除扫描到的文件

    /**
     * 处理window路径为标准路径
     * @param  mixed $dir 路径
     * @return mixed      标准路径
     */
    public static function strdir($str)
    {
        return str_replace(array('\\', '//', '//'), array('/', '/', '/'), chop($str));
    }

    /**
     * 记录日志
     * @param array $info 日记记录
     */
    public static function writeLog(array $info)
    {
        $time = date('Y-m-d H:i:s');
        array_unshift($info, $time);
        $info = array_map('json_encode', $info);
        file_put_contents('/tmp/' . 'webshellkill.log', implode(' | ', $info) . "\r\n", FILE_APPEND);
    }

    /**
     * 备份文件
     * @param string $source_path 源文件
     */
    public static function copyFile($source_path)
    {
        $file_name = substr($source_path, strrpos($source_path, '/') + 1);
        $target_path = '/tmp/' . $file_name . "-" . time() . ".bak";
        if (!file_exists('/tmp/')) {
            mkdir('/tmp/');
        }
        if (copy($source_path, $target_path)) {
            echo "{$source_path} 文件已备份 {$target_path} " . PHP_EOL;
            if (self::$isLog) {
                self::writeLog(array('backup file:', $source_path, $target_path));
            }
        }
    }

    /**
     * 查杀webshell主函数
     * @param  mixed $dir     查找目录
     * @param  mixed $exs     扩展名
     * @param  mixed $matches 正则表达式匹配数组,用于特征代码查找
     * @return mixed          返回值，查找完成返回true
     */
    public static function antivirus($dir, $exs, $matches)
    {
        if (($handle = @opendir($dir)) == null) {
            return false;
        }

        while (false !== ($name = readdir($handle))) {
            if ($name == '.' || $name == '..') {
                continue;
            }

            // 跳过扫描文件
            $path = $dir . $name;
            $fileName = isset($_SERVER['argv'][0]) ? $_SERVER['argv'][0] : ''; // cli模式获取文件名
            if (!empty($fileName) && (strpos($name, $fileName) !== false)) {
                echo '跳过文件: ' . $path . PHP_EOL;
                continue;
            }

            if (is_dir($path)) {
                if (is_readable($path)) {
                    self::antivirus($path . '/', $exs, $matches);
                }
            } else {
                // 扩展名过滤
                $fExt = pathinfo($name, PATHINFO_EXTENSION);
                if (!in_array(strtolower($fExt), $exs)) {
                    continue;
                }
                // 文件大小过滤
                if (filesize($path) > 10000000) {
                    continue;
                }
                // 打开文件
                echo '正在扫描: ' . $path . PHP_EOL;
                $fp = fopen($path, 'r');
                $fileSize = filesize($path);
                if ($fileSize <= 0) {
                    continue;
                }
                // 读取文件内容
                $code = fread($fp, filesize($path));
                fclose($fp);
                if (empty($code)) {
                    continue;
                }
                // 遍历所有正则表达式
                foreach ($matches as $matche) {
                    $matcheList = array();
                    // 正则表达式匹配
                    preg_match($matche, $code, $matcheList);
                    if (!$matcheList) {
                        continue;
                    }
                    // 排除一些特征码，如：$this->
                    if (strpos($matcheList[0], "\x24\x74\x68\x69\x73\x2d\x3e")) {
                        continue;
                    }
                    // 记录匹配到的文件
                    self::$matcheFileList[] = [
                        'code' => $matcheList[0],
                        'path' => $path,
                    ];
                    // 自动删除文件
                    if (self::$isDelFile) {
                        if (self::$isBak) { // 备份文件
                            self::copyFile($path);
                        }
                        unlink($path); // 删除文件
                        echo $path . '文件已删除' . PHP_EOL;
                        if (self::$isLog) {
                            self::writeLog(array('delete file:', $path));
                        }
                    }
                    break;
                }
                unset($code, $matcheList);
            }
        }
        closedir($handle);
        return false;
    }
}



ini_set('memory_limit', '512M');

// 没有定义扫描路径，则扫描当前目录
if (empty($scanDir)) {
    $scanDir = __DIR__;
}
/**
 * 代码中自定义特征代码进行查杀
 * 正表达式数组
 * 把webshell特征代码以正则表达式的方式写到该数组中，即可查找包含这些字符串的webshell
 * 如下方要查找的webshell包含：base64_decode(base64_decode 或包含 YUhSMGNEb3ZMM0JvY0dGd2F 或包含 thinkapi=base64_decode 或包含 @e#html这些字符串
 */
$matches = array(
    '/base64_decode(base64_decode/i',
    '/YUhSMGNEb3ZMM0JvY0dGd2F/i',
    '/thinkapi=base64_decode/i',
    '/@e#html/i',
);
// 定义了特征码，使用指定特征码
if (!empty($shellCode)) {
    $matches = array("/{$shellCode}/i");
}

$dir = ScanWebshell::strdir($scanDir . '/');
echo '扫描路径: ' . ($scanDir ? ScanWebshell::strdir($scanDir . '/') : ScanWebshell::strdir(__DIR__ . '/')) . PHP_EOL;
echo '文件类型: ' . (!empty($fileExt) ? json_encode($fileExt) : ['php']) . PHP_EOL;
echo '特征代码: ' . ($shellCode ? $shellCode : '') . PHP_EOL;
echo '正在扫描...' . PHP_EOL;

ScanWebshell::antivirus($dir, $fileExt, $matches);
echo PHP_EOL . PHP_EOL . PHP_EOL . PHP_EOL . PHP_EOL . PHP_EOL;
echo '--------------------------------------------------------';
echo PHP_EOL . PHP_EOL . PHP_EOL . PHP_EOL . PHP_EOL . PHP_EOL;
foreach (ScanWebshell::$matcheFileList as $k => $v) {
    echo '扫描到可疑文件: ' . $v['path'] . '  特征码: ' . $v['code'] . PHP_EOL;
}

echo PHP_EOL . '--------扫描完成--------' . PHP_EOL;
