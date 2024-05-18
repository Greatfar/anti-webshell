<?php

/**
 * webshell扫描器（基于特征代码）
 * 命令行模式运行，上传到服务器，执行 php scan.php 即可
 * @author Greatfar
 */
class ScanWebshell
{
    // 存在大量自动复制的webshell时，打开自动删除，非常有用
    public $isLog = true; // 是否记录日志
    public $isBak = true; // 备份被删除的文件
    public $isDelFile = false; // 自动删除扫描到的文件
    public $isEcho = true; // 自动删除扫描到的文件

    public $scanDir = '';
    public $fileExtList = [];
    public $matcheCodeList = [];
    public $matcheFileList = []; // 扫描命中的文件列表

    /**
     * 构造方法
     * @param string $shellCode 特征码
     * @param string $scanDir 扫描目录
     * @param array $fileExtList 扫描的文件扩展名
     */
    public function __construct($shellCode = null, $fileExtList = null, $isEcho = true, $isDelFile = false, $isLog = true, $isBak = true)
    {
        ini_set('memory_limit', '512M');

        $this->isLog = $isLog;
        $this->isDelFile = $isDelFile;
        $this->isBak = $isBak;
        $this->isEcho = $isEcho;

        if (is_null($fileExtList)) {
            $this->fileExtList = ['php', 'html', 'py'];
        } else {
            $this->fileExtList = $fileExtList;
        }

        /**
         * 代码中自定义特征代码进行查杀
         * 正表达式数组
         * 把webshell特征代码以正则表达式的方式写到该数组中，即可查找包含这些字符串的webshell
         * 如下方要查找的webshell包含：base64_decode(base64_decode 或包含 YUhSMGNEb3ZMM0JvY0dGd2F 或包含 thinkapi=base64_decode 或包含 @e#html这些字符串
         */
        if (is_null($shellCode)) {
            $this->matcheCodeList = [
                '/base64_decode(base64_decode/i',
                '/thinkapi=base64_decode/i',
                '/@e#html/i',
                '/eval/i',
            ];
        } else {
            $this->matcheCodeList = ["/{$shellCode}/i"];
        }

        echo '文件类型: ' . json_encode($this->fileExtList) . PHP_EOL;
        echo '特征代码: ' . $shellCode . PHP_EOL;
        echo '正在扫描...' . PHP_EOL;
    }

    /**
     * 处理window路径为标准路径
     * @param  mixed $dir 路径
     * @return mixed 标准路径
     */
    public function strdir($str)
    {
        return str_replace(['\\', '//', '//'], ['/', '/', '/'], chop($str));
    }

    /**
     * 记录日志
     * @param array $info 日记记录
     */
    public function writeLog(array $info)
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
    public function copyFile($source_path)
    {
        $file_name = substr($source_path, strrpos($source_path, '/') + 1);
        $target_path = '/tmp/' . $file_name . "-" . time() . ".bak";
        if (!file_exists('/tmp/')) {
            mkdir('/tmp/');
        }
        if (copy($source_path, $target_path)) {
            echo "{$source_path} 文件已备份 {$target_path} " . PHP_EOL;
            if ($this->isLog) {
                $this->writeLog(array('backup file:', $source_path, $target_path));
            }
        }
    }

    /**
     * 获取扫描结果
     */
    public function getScanRes()
    {
        return $this->matcheFileList;
    }

    /**
     * 查杀webshell主函数
     * @param  mixed $dir 查找目录
     * @param  mixed $exs 扩展名
     * @param  mixed $matches 正则表达式匹配数组,用于特征代码查找
     * @return mixed
     */
    public function antivirus($scanDir = null)
    {
        // 扫描目录
        if (is_null($scanDir)) {
            $scanDir = __DIR__;
        }
        $scanDir = $this->strdir($scanDir);
        // 打开目录
        if (($handle = @opendir($scanDir)) == null) {
            return false;
        }
        // 遍历目录
        while (false !== ($fileName = readdir($handle))) {
            if ($fileName == '.' || $fileName == '..') {
                continue;
            }
            // 完整路径
            $path = $scanDir . '/' . $fileName;
            // 如果是目录，递归调用扫描
            if (is_dir($path)) {
                if (is_readable($path)) {
                    $this->antivirus($path, $this->fileExtList, $this->matcheCodeList);
                }
            }
            // 如果是文件，读取文件内容，进行正则匹配
            else {
                // 跳过扫描器文件（本代码文件）
                $selfFileName = isset($_SERVER['argv'][0]) ? $_SERVER['argv'][0] : ''; // cli模式获取文件名
                if (!empty($selfFileName) && (strpos($path, $selfFileName) !== false)) {
                    echo '跳过文件: ' . $path . PHP_EOL;
                    continue;
                }
                // 扩展名过滤
                $fExt = pathinfo($fileName, PATHINFO_EXTENSION);
                if (!in_array($fExt, $this->fileExtList)) {
                    continue;
                }
                // 文件大小过滤
                if (filesize($path) > 100000000) {
                    continue;
                }
                // 打印扫描过程
                if ($this->isEcho) {
                    echo '正在扫描: ' . $path . PHP_EOL;
                }
                // 打开文件
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
                foreach ($this->matcheCodeList as $matche) {
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
                    $this->matcheFileList[] = [
                        'code' => $matcheList[0],
                        'path' => $path,
                    ];
                    // 自动删除文件
                    if ($this->isDelFile) {
                        if ($this->isBak) { // 备份文件
                            $this->copyFile($path);
                        }
                        unlink($path); // 删除文件
                        echo $path . '文件已删除' . PHP_EOL;
                        if ($this->isLog) {
                            $this->writeLog(array('delete file:', $path));
                        }
                    }
                    break;
                }
                unset($code, $matcheList);
            }
        }
        // 关闭目录
        closedir($handle);

        return true;
    }
}



// 扫描目录
// 大部分webshell都有error_reporting，但是有error_reporting不一定是webshell
// 特征码，如：error_reporting eval fwrite file_put_contents base64_decode
$scanWebshell = new ScanWebshell('error_reporting', ['php']);
$scanWebshell->antivirus('/data/www');
$resList = $scanWebshell->getScanRes();
// 打印扫描结果
if (!empty($resList)) {
    echo PHP_EOL . PHP_EOL . PHP_EOL . PHP_EOL . PHP_EOL . PHP_EOL;
    echo '-------------------------------------------------------';
    echo PHP_EOL . PHP_EOL . PHP_EOL . PHP_EOL . PHP_EOL . PHP_EOL;
}
foreach ($resList as $k => $v) {
    echo '扫描到可疑文件: ' . $v['path'] . '  特征码: ' . $v['code'] . PHP_EOL;
}
echo PHP_EOL . '--------扫描完成--------' . PHP_EOL;


