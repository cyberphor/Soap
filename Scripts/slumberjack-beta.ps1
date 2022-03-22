Param( 
    [switch]$Download, 
    [switch]$Remove
)

$Start = Get-Location
$DownloadFolder = "$env:ProgramData\slumberjack"
$SysmonFolder = "$env:ProgramData\Sysmon\"
$WinlogbeatFolder = "$env:ProgramData\Winlogbeat\"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Abort {
    Set-Location $Start
    break
}

function Check-Credentials {
    $UserId = [Security.Principal.WindowsIdentity]::GetCurrent()
    $AdminId = [Security.Principal.WindowsBuiltInRole]::Administrator
    $CurrentUser = New-Object Security.Principal.WindowsPrincipal($UserId)
    $RunningAsAdmin = $CurrentUser.IsInRole($AdminId)
    if (-not $RunningAsAdmin) { 
        Write-Output "`n[x] This script requires administrator privileges.`n"
        Abort
    }
}

function Check-Environment {
    if (Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue) {
        $SysmonIsInstalled = $true
    } else { $SysmonIsInstalled = $false }
    if (Get-Service -Name Winlogbeat -ErrorAction SilentlyContinue) {
        $WinlogbeatIsInstalled = $true
    } else { $WinlogbeatIsInstalled = $false } 
    if ($SysmonIsInstalled) { 
        if ($WinlogbeatIsInstalled) {
            Write-Output "`n[x] Sysmon and Winlogbeat are already installed."
            Abort
        } else {
            Write-Output "`n[x] Sysmon is installed, but Winlogbeat is not."
            Write-Output " ---> Try downloading and placing it under the same directory as 'slumberjack.ps1.'"
            Abort
        }
    } elseif ($WinlogbeatIsInstalled) { 
        Write-Output "`n[x] Winlogbeat is installed, but Sysmon is not."
        Write-Output " ---> Try downloading and placing it under the same directory as 'slumberjack.ps1.'"
        Abort
    }
}

function Create-Folders {
    $SysmonFolder, $WinlogbeatFolder | 
    ForEach-Object {
        if (Test-Path $_) { Remove-Item $_ -Recurse -Force }
        New-Item -Type Directory $_ | Out-Null
    }

    if (-not (Test-Path $DownloadFolder)) { 
        New-Item -Type Directory $DownloadFolder | Out-Null
    }
}

function Prepare-Software {
    $Sysmon = 'sysmon64.exe', 'Eula.txt'
    $SysmonConfig = 'sysmonconfig-export.xml'
    $Winlogbeat = 'winlogbeat.exe'
    $Software = $Sysmon + $SysmonConfig + $Winlogbeat
    $CurrentDirectory = Get-ChildItem $pwd -Recurse
    $slumberjack = Get-ChildItem $DownloadFolder -Recurse
    $FilesFound = @()
    $FilesMissing = @()
    $FilesToDownload = @{}

    $Software | ForEach-Object {
        $File = $_
        if ($CurrentDirectory.Name -contains $File) {
            $FilesFound += $CurrentDirectory | Where-Object { $_.Name -eq $File }
        } elseif ($slumberjack.Name -contains $File) {
            $FilesFound += $slumberjack | Where-Object { $_.Name -eq $File }
        } else {
            $FilesMissing += $File
        }
    }

    $FilesFound | ForEach-Object {
        if ($_.Directory.Name -notlike ($DownloadFolder)) {
            Copy-Item $_.FullName -Destination $DownloadFolder
        }
    }

    $FilesMissing | ForEach-Object {
        if (($Sysmon -contains $_) -and ($FilesToDownload.Keys -notcontains 'Sysmon')) { 
            $FilesToDownload.Add('Sysmon','https://download.sysinternals.com/files/Sysmon.zip') 
        }
    
        elseif (($SysmonConfig -contains $_) -and ($FilesToDownload.Keys -notcontains 'Sysmon-config')) { 
            $FilesToDownload.Add('Sysmon-config','https://github.com/SwiftOnSecurity/sysmon-config/archive/master.zip') 
        }

        elseif (($Winlogbeat -contains $_) -and ($FilesToDownload.Keys -notcontains 'Winlogbeat')) { 
            $FilesToDownload.Add('Winlogbeat','https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-7.7.0-windows-x86_64.zip') 
        }
    }

    if ($Download) {
        $FilesToDownload.GetEnumerator() | 
        ForEach-Object {
            $ZipFile = '.\' + $_.Key + '.zip'
            Invoke-WebRequest -Uri $_.Value -OutFile $ZipFile
            if (Test-Path $ZipFile) { 
                Unblock-File $ZipFile
                Expand-Archive $ZipFile
                Remove-Item -Recurse $ZipFile
            } else {
                Write-Output "`n[x] Failed to download $ZipFile."
                Write-Output " --->  Is the URL still valid?`n"
                Abort
            }
        }
    }

    Get-ChildItem $pwd -Recurse | 
    ForEach-Object {
        if ($_.Name -in $FilesMissing) {
            Copy-Item $_.Fullname -Destination $DownloadFolder
        }
    }
     
    '.\Sysmon','.\Sysmon-config','.\Winlogbeat' | 
    ForEach-Object { if (Test-Path $_) { Remove-Item -Recurse $_ } }
}

function Install-Sysmon {
    if (Test-Path "$DownloadFolder\Sysmon64.exe") {
        Copy-Item -Path "$DownloadFolder\Sysmon64.exe", "$DownloadFolder\Eula.txt", "$DownloadFolder\sysmonconfig-export.xml" -Destination $SysmonFolder
        $SysmonArguments = '/accepteula', '-i', "$SysmonFolder\sysmonconfig-export.xml"
        Start-Process -FilePath "$SysmonFolder\Sysmon64.exe" -ArgumentList $SysmonArguments -Wait
        Start-Service Sysmon64
    } else { 
        Write-Output "`n[x] Failed to find Sysmon."
        Write-Output " --->  Try downloading and placing it under the same directory as 'slumberjack.ps1.'"
        Abort    
    }
}

function Create-WinlogbeatConfig {
    $LogstashHost = Read-Host -Prompt "[+] Logstash Host"
    New-Item -Name "winlogbeat.yml" -Path $WinlogbeatFolder | Out-Null
    "winlogbeat.event_logs:",
    "  - name: Microsoft-Windows-Sysmon/Operational",
    "output.logstash:",
    ('  hosts: ["' + $LogstashHost + ':5044"]') |
    ForEach-Object { Add-Content -Path "$WinlogbeatFolder\winlogbeat.yml" -Value $_ }
}

function Install-Winlogbeat {
    if (Test-Path "$DownloadFolder\winlogbeat.exe") {
        Create-WinlogbeatConfig
        Copy-Item -Path "$DownloadFolder\winlogbeat.exe" -Destination $WinlogbeatFolder
        $Binary = "$WinlogbeatFolder\winlogbeat.exe"
        $Config = "$WinlogbeatFolder\winlogbeat.yml"
        $HomePath = "$WinlogbeatFolder"
        $DataPath = "$WinlogbeatFolder\Data"
        $LogsPath = "$WinlogbeatFolder\Data\logs"
        $BinaryPathName = "$Binary -c $Config -path.home $HomePath -path.data $DataPath -path.logs $LogsPath"
        New-Service -Name Winlogbeat -DisplayName Winlogbeat -BinaryPathName $BinaryPathName | Out-Null
        Set-Service -Name Winlogbeat -StartupType Automatic
        Start-Service Winlogbeat
    } else { 
        Write-Output "`n[x] Failed to find Winlogbeat."
        Write-Output " --->  Try downloading and placing it under the same directory as 'slumberjack.ps1.'"
        Abort
    }
}

function Remove-slumberjack {
    if (Get-Service -Name Winlogbeat -ErrorAction SilentlyContinue) {
        Stop-Service Winlogbeat
        (Get-WmiObject -Class Win32_Service -Filter "name='Winlogbeat'").Delete() | Out-Null
    }
    if (Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue) {
        Stop-Service Sysmon64
        (Get-WmiObject -Class Win32_Service -Filter "name='Sysmon64'").Delete() | Out-Null
        Start-Process -FilePath "$SysmonFolder\Sysmon64.exe" -ArgumentList '-u force' -NoNewWindow -Wait
    }
    if (Test-Path $WinlogbeatFolder) { Remove-Item -Path $WinlogbeatFolder -Recurse -Force }
    if (Test-Path $SysmonFolder) { Remove-Item -Path $SysmonFolder -Recurse -Force }
    if (Test-Path $DownloadFolder) { Remove-Item -Path $DownloadFolder -Recurse -Force }
}

Check-Credentials
if ($Remove) { Remove-slumberjack }
else {
    Check-Environment
    Create-Folders
    Prepare-Software
    Install-Sysmon
    Install-Winlogbeat
}
Abort
