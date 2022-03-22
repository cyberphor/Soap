Param(
    [switch]$DownloadOnly,
    [string]$EventCollector=$env:COMPUTERNAME,
    [ipaddress]$ElasticHost='127.0.0.1'
)

$Start = Get-Location
$DownloadFolder = 'Slumberjack'

function CheckIf-DomainAdmin {
    $UserId = [Security.Principal.WindowsIdentity]::GetCurrent()
    $AdminId = [Security.Principal.WindowsBuiltInRole]::Administrator
    $CurrentUser = New-Object Security.Principal.WindowsPrincipal($UserId)
    $RunningAsAdmin = $CurrentUser.IsInRole($AdminId)
    if (-not $RunningAsAdmin) { 
        Write-Output "`n[x] This script requires administrator privileges.`n"
        Abort
    }
}

function CheckIf-DomainController {
    $ProductType = (Get-WmiObject -Class Win32_OperatingSystem).ProductType
    if ($ProductType -ne 2) {
        Write-Output "`n[x] This script must be executed on a Domain Controller.`n"
        Abort
    }
}

function Download-Software {
    $Sysmon = 'sysmon.exe', 'sysmon64.exe', 'Eula.txt'
    $SysmonConfig = 'sysmonconfig-export.xml'
    $Winlogbeat = 'winlogbeat.exe', 'winlogbeat.yml'
    $Slumberjack = 'Install-Sysmon.ps1', 'sysmonsubscription.xml', 'Install-Winlogbeat.ps1'
    $Software = $Sysmon + $SysmonConfig + $Winlogbeat + $Slumberjack
    $CurrentDirectory = Get-ChildItem $pwd -Recurse
    $Found = @()
    $Missing = @()
    $Download = @{}

    if (-not (Test-Path $DownloadFolder)) { 
        New-Item -ItemType Directory $DownloadFolder | Out-Null
    }

    $Software | ForEach-Object {
        $File = $_
        if ($CurrentDirectory.Name -contains $File) {
            $Found += $CurrentDirectory | Where-Object { $_.Name -eq $File }
        } else {
            $Missing += $File
        }
    }

    $Found | ForEach-Object {
        if ($_.Directory.Name -notlike $DownloadFolder) {
            Copy-Item $_.FullName -Destination ".\$DownloadFolder"
        }
    }

    $Missing | ForEach-Object {
        if (($Sysmon -contains $_) -and ($Download.Keys -notcontains 'Sysmon')) { 
            $Download.Add('Sysmon','https://download.sysinternals.com/files/Sysmon.zip') 
        }
    
        elseif (($SysmonConfig -contains $_) -and ($Download.Keys -notcontains 'Sysmon-config')) { 
            $Download.Add('Sysmon-config','https://github.com/SwiftOnSecurity/sysmon-config/archive/master.zip') 
        }

        elseif (($Winlogbeat -contains $_) -and ($Download.Keys -notcontains 'Winlogbeat')) { 
            $Download.Add('Winlogbeat','https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-6.2.4-windows-x86_64.zip ') 
        }

        elseif (($Slumberjack -contains$_) -and ($Download.Keys -notcontains 'SlumberjackFiles')){ 
            $Download.Add('SlumberjackFiles','https://github.com/cyberphor/Slumberjack/archive/master.zip')     
        }
    }

    $Download.GetEnumerator() | 
    ForEach-Object {
        $ZipFile = '.\' + $_.Key + '.zip'
        Invoke-WebRequest -Uri $_.Value -OutFile $ZipFile
        Unblock-File $ZipFile
        Expand-Archive $ZipFile
        Remove-Item -Recurse $ZipFile
    }

    Get-ChildItem $pwd -Recurse | 
    ForEach-Object {
        if ($_.Name -in $Missing) {
            Copy-Item $_.Fullname -Destination $DownloadFolder
        }
    }
     
    '.\Sysmon','.\Sysmon-config','.\Winlogbeat','.\SlumberjackFiles' | 
    ForEach-Object { if (Test-Path $_) { Remove-Item -Recurse $_ } }
}

function Deploy-Sysmon {
    $Policy = 'Deploy-Sysmon'
    $Script = 'Install-Sysmon.ps1'
    $Comment = 'Uses a "Startup" script to install and configure the "Sysmon" service.'
    $Files = @(
        ".\$DownloadFolder\$Script", 
        ".\$DownloadFolder\Eula.txt",
        ".\$DownloadFolder\Sysmon.exe", 
        ".\$DownloadFolder\Sysmon64.exe",
        ".\$DownloadFolder\sysmonconfig-export.xml"
    )

    if (Test-Path ".\$DownloadFolder\$Script") {
        New-GPO -Name $Policy -Comment $Comment

        $Domain = (Get-WmiObject -Class Win32_ComputerSystem).Domain
        $Sysvol = "$env:SystemRoot\SYSVOL\sysvol\$Domain\Policies"
        $Guid = (Get-GPO -Name $Policy).Id.Guid
        $Gpo = "$Sysvol\{$Guid}"
        $MachineFolder = "$Gpo\Machine"
        $ScriptsFolder = "$Gpo\Machine\Scripts"
        $StartupScriptsFolder = "$ScriptsFolder\Startup"

        New-Item -ItemType Directory -Name 'Scripts' -Path $MachineFolder
        New-Item -ItemType Directory -Name 'Startup' -Path $ScriptsFolder
        Copy-Item $Files -Destination $StartupScriptsFolder

        $PsscriptsFile = "$ScriptsFolder\psscripts.ini"
        '','[Startup]',"0CmdLine=$Script",'0Parameters=' | Out-File -Encoding unicode $PsscriptsFile 
        $PsscriptsFile = Get-Item $PsscriptsFile
        $PsscriptsFile.Attributes = 'Hidden'

        $GptFile = "$Gpo\GPT.ini"
        $OldVersion = '0'
        $NewVersion = '2'
        (Get-Content -Path $GptFile) -replace $OldVersion, $NewVersion | Set-Content -Path $GptFile

        $SearchAdsi = New-Object DirectoryServices.DirectorySearcher
        $SearchAdsi.Filter = "(&(objectCategory=groupPolicyContainer)(Name={$Guid}))"
        $GpoInAd = $SearchAdsi.FindAll().Item(0)
        $GpoInAd = $GpoInAd.GetDirectoryEntry()
        $GuidPairForClientAndMmcSnapIn = '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]'
        $GpoInAd.Properties['gpcmachineextensionnames'].Value = $GuidPairForClientAndMmcSnapIn
        $GpoInAd.Properties['versionNumber'].Value = $NewVersion
        $GpoInAd.CommitChanges()

        $Ou = (Get-ADDomain -Current LocalComputer).DistinguishedName
        New-GPLink -Name $Policy -Target $Ou
    }
}

function Enable-WinRM {
    $Policy = 'Enable-WinRM'
    $Comment = 'Enables and configures the "Windows Remote Management (WinRM)" service.'
    New-GPO $Policy -Comment $Comment

    $Key = 'HKLM\Software\Policies\Microsoft\Windows\WinRM\Service'
    $ValueName = 'AllowAutoConfig'
    $Value = 1
    $Type = 'Dword'
    Set-GPRegistryValue -Name $Policy -Key $Key -ValueName $ValueName -Value $Value -Type $Type

    $ValueName = 'IPv4Filter'
    $Value = '*'
    $Type = 'String'
    Set-GPRegistryValue -Name $Policy -Key $Key -ValueName $ValueName -Value $Value -Type $Type

    $ValueName = 'IPv6Filter'
    $Value = '*'
    $Type = 'String'
    Set-GPRegistryValue -Name $Policy -Key $Key -ValueName $ValueName -Value $Value -Type $Type

    $fwrule = 'v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=5985|'
    'App=System|Name=@FirewallAPI.dll,-30253|Desc=@FirewallAPI.dll'
    $fwrule += ',-30256|EmbedCtxt=@FirewallAPI.dll,-30252'
    $Key = 'HKLM\Software\Policies\Microsoft\WindowsFirewall\FirewallRules'    
    $ValueName = 'WINRM-HTTP-In-TCP'
    $Value = $fwrule
    $Type = 'String'
    Set-GPRegistryValue -Name $Policy -Key $Key -ValueName $ValueName -Value $Value -Type $Type

    $Key = 'HKLM\SYSTEM\CurrentControlSet\Services\WinRM'    
    $ValueName = 'Start'
    $Value = 2
    $Type = 'Dword'
    Set-GPRegistryValue -Name $Policy -Key $Key -ValueName $ValueName -Value $Value -Type $Type

    $Ou = (Get-ADDomain -Current LocalComputer).DistinguishedName
    New-GPLink -Name $Policy -Target $Ou
}

function Configure-WEF {
    $Policy = 'Configure-WEF'
    $Comment = 'Configures "Windows Event Forwarding."'
    New-GPO -Name $Policy -Comment $Comment

    $Key = 'HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
    $Server = ([System.Net.Dns]::GetHostByName(($EventCollector))).Hostname
    $Value = 'Server=http://' + $Server + ':5985/wsman/SubscriptionManager/WEC,Refresh=10'
    $Type = 'String'
    Set-GPRegistryValue -Name $Policy -Key $Key -Value $Value -Type $Type

    $Ou = (Get-ADDomain -Current LocalComputer).DistinguishedName
    New-GPLink -Name $Policy -Target $Ou
}

function Deploy-EventCollectors {
    $GroupName = 'Event Collectors'
    $GroupScope = 'Global'
    $GroupCategory = 'Security'
    $Description = 'Members of this group collect Sysmon logs and share them via Winlogbeat.'

    if (-not (Get-ADGroup -Filter {Name -eq $GroupName})) {
        New-ADGroup -Name $GroupName `
            -SamAccountName $GroupName `
            -DisplayName $GroupName `
            -GroupScope $GroupScope `
            -GroupCategory $GroupCategory `
            -Description $Description
    }
    
    if (-not (Get-ADGroup -Filter {Name -eq $GroupName -and Member -like $EventCollector})) {
        $Member = $EventCollector + '$'
        Add-ADGroupMember $GroupName -Members $Member
    }

    $Policy = 'Deploy-EventCollectors'
    $Script = 'Install-Winlogbeat.ps1'
    $Comment = 'Enables the "Windows Event Collection" service and installs "Winlogbeat."'
    $Files = @(
        ".\$DownloadFolder\$Script";
        ".\$DownloadFolder\winlogbeat.yml";
        ".\$DownloadFolder\winlogbeat.exe";
        ".\$DownloadFolder\sysmonsubscription.xml"
    ) 

    $ConfigFile = "$DownloadFolder\winlogbeat.yml"

    if (Test-Path $ConfigFile) {
        $Config = Get-Content $ConfigFile

        $Config = $Config.Replace('winlogbeat.event_logs:',"winlogbeat.event_logs:`n  -name: ForwardedEvents")
        $Config = $Config.Replace('- name: Application','#- name: Application')
        $Config = $Config.Replace('ignore_older: 72h','#ignore_older: 72h')
        $Config = $Config.Replace('- name: Security','#- name: Security')
        $Config = $Config.Replace('- name: System','#- name: System')
        $Config = $Config.Replace('setup.template.settings:','#setup.template.settings:')
        $Config = $Config.Replace('index.number_of_shards: 3','#index.number_of_shards: 3')
        $Config = $Config.Replace('setup.kibana:','#setup.kibana:')
        $Config = $Config.Replace('output.elasticsearch:','#output.elasticsearch:')
        $Config = $Config.Replace('hosts: ["localhost:9200"]','#hosts: ["localhost:9200"]')
        $Config = $Config.Replace('#output.logstash:','output.logstash:')
        $Config = $Config.Replace('#hosts: ["localhost:5044"]','hosts: ["' + $ElasticHost + ':5044"]')

        $Config | Out-File ".\foo.yml"
    }

    if (Test-Path ".\$DownloadFolder\$Script") {
        New-GPO -Name $Policy -Comment $Comment

        $Domain = (Get-WmiObject -Class Win32_ComputerSystem).Domain
        $Sysvol = "$env:SystemRoot\SYSVOL\sysvol\$Domain\Policies"
        $Guid = (Get-GPO -Name $Policy).Id.Guid
        $Gpo = "$Sysvol\{$Guid}"
        $MachineFolder = "$Gpo\Machine"
        $ScriptsFolder = "$Gpo\Machine\Scripts"
        $StartupScriptsFolder = "$ScriptsFolder\Startup"

        New-Item -ItemType Directory -Name 'Scripts' -Path $MachineFolder
        New-Item -ItemType Directory -Name 'Startup' -Path $ScriptsFolder
        Copy-Item $Files -Destination $StartupScriptsFolder

        $PsscriptsFile = "$ScriptsFolder\psscripts.ini"
        '','[Startup]',"0CmdLine=$Script",'0Parameters=' | Out-File -Encoding unicode $PsscriptsFile 
        $PsscriptsFile = Get-Item $PsscriptsFile
        $PsscriptsFile.Attributes = 'Hidden'

        $GptFile = "$Gpo\GPT.ini"
        $OldVersion = '0'
        $NewVersion = '2'
        (Get-Content -Path $GptFile) -replace $OldVersion, $NewVersion | Set-Content -Path $GptFile

        $SearchAdsi = New-Object DirectoryServices.DirectorySearcher
        $SearchAdsi.Filter = "(&(objectCategory=groupPolicyContainer)(Name={$Guid}))"
        $GpoInAd = $SearchAdsi.FindAll().Item(0)
        $GpoInAd = $GpoInAd.GetDirectoryEntry()
        $GuidPairForClientAndMmcSnapIn = '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]'
        $GpoInAd.Properties['gpcmachineextensionnames'].Value = $GuidPairForClientAndMmcSnapIn
        $GpoInAd.Properties['versionNumber'].Value = $NewVersion
        $GpoInAd.CommitChanges()

        $GroupName = 'Event Collectors'
        Set-GPPermissions -Name $Policy -Replace -PermissionLevel GpoRead -TargetName 'Authenticated Users' -TargetType Group
        Set-GPPermissions -Name $Policy -PermissionLevel GpoApply -TargetName $GroupName -TargetType Group

        $Ou = (Get-ADDomain -Current LocalComputer).DistinguishedName
        New-GPLink -Name $Policy -Target $Ou
    }
}

function Abort {
    Set-Location $Start
    break
}

Clear-Host

if ($DownloadOnly) { Download-Software } 
else {
    CheckIf-DomainAdmin
    CheckIf-DomainController
    Download-Software
    Deploy-Sysmon
    Enable-WinRM
    Configre-WEF
    Deploy-EventCollectors
}

Abort
