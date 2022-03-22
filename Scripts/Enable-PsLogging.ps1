Param([Parameter(Mandatory = $false)][switch]$Disable)

$BlockLogging = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 
$ModuleLogging = 'HKLM:\Software\WOW6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging'

function Get-Credentials {
    $UserId = [Security.Principal.WindowsIdentity]::GetCurrent()
    $AdminId = [Security.Principal.WindowsBuiltInRole]::Administrator
    $CurrentUser = New-Object Security.Principal.WindowsPrincipal($UserId)
    $RunningAsAdmin = $CurrentUser.IsInRole($AdminId)
    if (-not $RunningAsAdmin) { 
        Write-Output "[x] This script requires administrator privileges."
        break
    }
}

function Enable-PsBlockLogging {
    if(-not (Test-Path $BlockLogging)) {      
        New-Item $BlockLogging | Out-Null
        New-ItemProperty $BlockLogging -Name 'EnableScriptBlockLogging' -PropertyType Dword | Out-Null
    } 

    Set-ItemProperty $BlockLogging -Name 'EnableScriptBlockLogging' -Value '1'
    if ((Get-ItemProperty $BlockLogging).EnableScriptBlockLogging -eq '1') {
        Write-Host '[+] Enabled PowerShell Script Block logging.'
    }
}

function Enable-PsModuleLogging {
    if(-not (Test-Path $ModuleLogging)) {
        New-Item $ModuleLogging -Force | Out-Null
        New-ItemProperty $ModuleLogging -Name 'EnableModuleLogging' -PropertyType Dword | Out-Null
    }

    Set-ItemProperty $ModuleLogging -Name 'EnableModuleLogging' -Value '1'
    if ((Get-ItemProperty $ModuleLogging).EnableModuleLogging -eq '1') {
        Write-Host '[+] Enabled PowerShell Module logging.'
    }
}

function Disable-PsBlockLogging {
    Set-ItemProperty $BlockLogging -Name 'EnableScriptBlockLogging' -Value '0'
    if ((Get-ItemProperty $BlockLogging).EnableScriptBlockLogging -eq '0') {
        Write-Host '[+] Disabled PowerShell Script Block logging.'
    }

}

function Disable-PsModuleLogging {
    Set-ItemProperty $ModuleLogging -Name 'EnableModuleLogging' -Value '0'
    if ((Get-ItemProperty $ModuleLogging).EnableModuleLogging -eq '0') {
        Write-Host '[+] Disabled PowerShell Module logging.'
    }
}

if ($Disable) {
    Disable-PsBlockLogging
    Disable-PsModuleLogging
} else {
    Enable-PsBlockLogging
    Enable-PsModuleLogging
}
