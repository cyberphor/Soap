$Service = 'Winlogbeat'
$Installed = Get-Service | Where-Object { $_.Name -like $Service }
$RunStatus = $Installed.Status

if ($Installed) {
    if ($RunStatus -ne "Running") { Start-Service -Name $Service } 
} else {
    $LocalFolder = "$env:ProgramData\$Service"
    if (Test-Path $LocalFolder) { Remove-Item -Recurse $LocalFolder }
    else { New-Item -Type Directory $LocalFolder | Out-Null }

    $Domain = (Get-WmiObject Win32_ComputerSystem).Domain
    $AllGpoFiles = Get-ChildItem -Recurse "\\$Domain\sysvol\$Domain\Policies\"
    $ServiceGPO = ($AllGpoFiles | Where-Object { $_.Name -eq "$Service.exe" }).DirectoryName
    Copy-Item -Path "$ServiceGPO\winlogbeat.exe", "$ServiceGPO\winlogbeat.yml", "$ServiceGPO\sysmonsubscription.xml" -Destination $LocalFolder
 
    if (Test-Path "$LocalFolder\$Service.exe") {
        $Binary = "$LocalFolder\$Service.exe"
        $Config = "$LocalFolder\winlogbeat.yml"
        $PathHome = "$LocalFolder"
        $PathData = "$LocalFolder\Data"
        $PathLogs = "$LocalFolder\Data\logs"
        $BinaryPathName = "$Binary -c $Config -path.home $PathHome -path.data $PathData -path.logs $PathLogs"
        New-Service -Name $Service -DisplayName $Service -BinaryPathName $BinaryPathName
        Set-Service -Name $Service -StartupType Automatic
        Start-Service -Name $Service
    }
}

if ((Get-Service Wecsvc).Status -ne 'Running') { Start-Service Wecsvc }

$Subscriptions = wecutil es
$SysmonSubscription = "$env:ProgramData\Winlogbeat\sysmonsubscription.xml"
if (($Subscriptions -notcontains 'Sysmon') -and (Test-Path $SysmonSubscription)) { 
    wecutil cs $SysmonSubscription 
}

netsh http delete urlacl url=http://+:5985/wsman/
$sddl = 'sddl=D:(A;;GX;;;S-1-5-80-569256582-2953403351-2909559716-1301513147-412116970)(A;;GX;;;S-1-5-80-4059739203-877974739-1245631912-527174227-2996563517)'
netsh http add urlacl url=http://+:5985/wsman/ $sddl
