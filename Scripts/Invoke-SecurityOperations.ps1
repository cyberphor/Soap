
function Get-Credentials {
    $UserId = [Security.Principal.WindowsIdentity]::GetCurrent()
    $AdminId = [Security.Principal.WindowsBuiltInRole]::Administrator
    $CurrentUser = New-Object Security.Principal.WindowsPrincipal($UserId)
    $RunningAsAdmin = $CurrentUser.IsInRole($AdminId)
    if (-not $RunningAsAdmin) { 
        Write-Output "`n[x] This script requires administrator privileges.`n"
        break
    }
}

function Start-SecurityOperations {

    $ScriptsFolder = "C:\Users\Public\Documents\Scripts"
    $CurrentLocation = (Get-Location).Path

    if ($CurrentLocation -ne $ScriptsFolder) {
        Set-Location $ScriptsFolder
    }

    $Index = 0
    $Options = @{}
    $Scripts = Get-ChildItem |
    Where-Object { $_.Name -like '*.ps1' } |
    Select -ExpandProperty Name | 
    Sort-Object |
    ForEach-Object {
        if ($_ -ne $MyInvocation.MyCommand.Name) {
            $Index = $Index + 1
            $Options.Add($Index.ToString(),$_)
        }
    }

    Write-Host "[+] Pick a script: "
    $Options.GetEnumerator() |
    Sort-Object { [int]$_.Key } |
    ForEach-Object {
        Write-Host $(' ' + $_.Key.ToString() + '  ' + $_.Value.ToString())
    }

    $Choice = Read-Host ' --> Choice'

    if ($Options.Keys -contains $Choice) {
        $Script = $Options.$Choice
        powershell.exe ".\$Script"
    }

    Set-Location $CurrentLocation

}

Get-Credentials
Start-SecurityOperations

<# REFERENCES
https://stackoverflow.com/questions/817198/how-can-i-get-the-current-powershell-executing-file
#>
