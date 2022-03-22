Param(
    [string]$From,
    [switch]$FromGroupPolicy,
    [switch]$Remove
)

function Install-Program($Source) {
    if (Test-Path $Source) {
        $Directory = @{}
        Get-ChildItem $Source -Recurse | 
        Select -Property Name, FullName |
        ForEach-Object {
            if ($Directory.Keys -notcontains $_.Name) {
                $Directory.Add($_.Name, $_.FullName)
            }
        }
    } else {
        Write-Host "[x] Folder does not exist: $Source"
    }
     
    $FilesToCopy = @()
    $Requirements | ForEach-Object {
        $RequiredFile = $_ 
        if ($Directory.Keys -contains $RequiredFile) {
            $FilesToCopy += $Directory.Item($RequiredFile)
        } else {
            Write-Host "[x] Missing required file: $RequiredFile"
            exit
        }
    }

    if (Test-Path $InstallationFilePath) { 
        Remove-Item -Recurse $InstallationFilePath
    } 
    New-Item -ItemType Directory -Path $InstallationFilePath | Out-Null

    if (Test-Path $RunTimeFilePath) { 
        Remove-Item -Recurse $RunTimeFilePath
    } 
    New-Item -ItemType Directory -Path $RunTimeFilePath | Out-Null

    $FilesToCopy | ForEach-Object {
        $RequiredFile = $_
        Copy-Item -Path $RequiredFile -Destination $InstallationFilePath
    }

    $Configuration = @(
        "name: '$Shipper'",
        "tags: ['$Tag']",
        "winlogbeat.event_logs:",
        "- name: $Log",
        "output.logstash:", 
        "   hosts: ['$LogstashServer']"
    ) -join "`r`n"

    Add-Content -Value $Configuration -Path $ConfigurationFilePath

    if (Test-Path "$InstallationFilePath\$Program") {
        $Binary = "`"$InstallationFilePath\$Program`""
        $Arguments = " -c `"$ConfigurationFilePath`" -path.home `"$RunTimeFilePath`" -path.data `"$RunTimeFilePath`" -path.logs `"$RunTimeFilePath`""
        $BinaryPathName = $Binary + $Arguments
        
        New-Service -Name $Name -DisplayName $Name -Description $Description -BinaryPathName $BinaryPathName | Out-Null
        Start-Service $Name | Out-Null
        Write-Host "[+] Deployed $Name."
        Write-Host " -  Source: $Log"
        Write-Host " -  Destination: $LogstashServer"
    }
}

function Start-Program {
    if ($ServiceIsInstalled.Status -ne "Running") { 
        Start-Service -Name $Name 
    } else {
        Write-Host "[+] $Name is already running."
    }
}

function Remove-Program {
    if ($ServiceIsInstalled) {
        Stop-Service $Name
        (Get-WmiObject -Class Win32_Service -Filter "name='$Name'").Delete() | Out-Null
        Remove-Item -Path $RunTimeFilePath -Recurse -Force
        Remove-Item -Path $InstallationFilePath -Recurse -Force
        Write-Host "[+] Removed $Name."
    } else {
        Write-Host "[x] $Name is not installed."
    }
}

function Main {
    $Name = 'Winlogbeat'
    $Description = 'Ships Windows event logs to Elasticsearch or Logstash.'  
    $Program = $Name.ToLower() + '.exe'
    $ConfigurationFile = $Name.ToLower() + '.yml'
    $Requirements = $Program
    
    $InstallationFilePath = $env:ProgramFiles + '\' + $Name
    $ConfigurationFilePath = $InstallationFilePath + '\' + $ConfigurationFile
    $RunTimeFilePath = $env:ProgramData + '\' + $Name

    $ServiceIsInstalled = Get-Service | Where-Object { $_.Name -like $Name }
    
    $Shipper = $env:COMPUTERNAME 
    # --- CUSTOMIZE FOR YOUR ENVIRONMENT --- #
    $Tag = 'winlogbeat'
    $Log = 'ForwardedEvents'
    $IpAddress = '192.168.3.12'
    $Port = '5044'
    # -------------------------------------- #
    $LogstashServer = $IpAddress + ':' + $Port

    if ($Remove) {
        Remove-Program 
    } elseif ($ServiceIsInstalled) { 
        Start-Program
    } elseif ($FromGroupPolicy) {
        $Domain = (Get-WmiObject Win32_ComputerSystem).Domain
        $SysVol = Get-ChildItem -Recurse "\\$Domain\sysvol\$Domain\Policies\"
        $GroupPolicyObject = ($SysVol | Where-Object { $_.Name -eq $Program }).DirectoryName
        Install-Program($GroupPolicyObject)
    } elseif ($From) {
        Install-Program($From)
    } else {
        Install-Program($PWD)
    }
}

Main

# REFERENCES
# https://stackoverflow.com/questions/52113738/starting-ssh-agent-on-windows-10-fails-unable-to-start-ssh-agent-service-erro
# https://stackoverflow.com/questions/2022326/terminating-a-script-in-powershell
# https://stackoverflow.com/questions/26372360/powershell-script-indentation-for-long-strings
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-service?view=powershell-7
# https://www.elastic.co/guide/en/beats/filebeat/current/command-line-options.html
# https://www.elastic.co/guide/en/beats/filebeat/current/configuration-filebeat-options.html
