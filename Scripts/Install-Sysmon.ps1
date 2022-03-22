$Service = 'Sysmon'
$OSArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
if ($OSArchitecture -ne '32-bit') { $Service = $Service + '64' }
$Installed = Get-Service | Where-Object { $_.Name -like $Service }
$RunStatus = $Installed.Status

if ($Installed) {
    if ($RunStatus -ne "Running") { Start-Service -Name $Service }
} else {
    $LocalFolder = "$env:ProgramData\$Service\"
    if (Test-Path $LocalFolder) { Remove-Item -Recurse $LocalFolder }
    else { New-Item -Type Directory $LocalFolder | Out-Null }

    $Domain = (Get-WmiObject Win32_ComputerSystem).Domain
    $AllGpoFiles = Get-ChildItem -Recurse "\\$Domain\sysvol\$Domain\Policies\"
    $ServiceGPO = ($AllGpoFiles | Where-Object { $_.Name -eq "$Service.exe" }).DirectoryName
    Copy-Item -Path "$ServiceGPO\$Service.exe", "$ServiceGPO\Eula.txt", "$ServiceGPO\sysmonconfig-export.xml" -Destination $LocalFolder
    
    if (Test-Path "$LocalFolder\$Service.exe") {
        $ServiceArguments = '/accepteula', '-i', "$LocalFolder\sysmonconfig-export.xml"
        Start-Process -FilePath "$LocalFolder\$Service.exe" -ArgumentList $ServiceArguments -NoNewWindow -Wait

        $Binary = 'C:\Windows\System32\wevtutil.exe'
        $Option = 'sl'
        $LogName = 'Microsoft-Windows-Sysmon/Operational'
        $LogPermissions = '/ca:O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;BO)(A;;0x1;;;SO)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;S-1-5-20)'
        $BinaryArguments = $Option, $LogName, $LogPermissions
        Start-Process -Filepath $Binary -ArgumentList $BinaryArguments -NoNewWindow -Wait
    }
}
