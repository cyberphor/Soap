# https://github.com/SirAddison/PoSh

$RegistryKeys = @(
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
    "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
    "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell",
    "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell",
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices\",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"
)

$AutoRunsFound = @{}

$RegistryKeys | 
ForEach-Object {
    $RegistryKey = $_ 
    if (Test-Path $RegistryKey) {
        $AutoRunsExist = Get-Item $RegistryKey | Select -ExpandProperty Property

        if ($AutoRunsExist) {
            $Count = (Get-Item $RegistryKey).Property.Count 
            (Get-Item $RegistryKey).Property[0..$Count] |
            ForEach-Object { 
                $App = $_
                $AppPath = (Get-ItemProperty $RegistryKey).$App 
                $AutoRunsFound.Add($App,$AppPath)
            }
        }
    }
}

$AutoRunsFound | Out-File "$env:USERPROFILE\Desktop\AutoRuns.txt"
