function Edit-CustomModule {
    param([string]$Name)
    $Module = "C:\Program Files\WindowsPowerShell\Modules\$Name\$Name.psm1"
    $Expression = 'powershell_ise.exe "$Module"'
    if (Test-Path -Path $Module) {
        Invoke-Expression $Expression
    } else {
        Write-Output "[x] The $Name module does not exist."
    }
}

function Get-CustomModule {
    param([string]$Name)
    Get-Module -ListAvailable | 
    Where-Object { $_.Path -like "C:\Program Files\WindowsPowerShell\Modules\*$Name*" }
}

function Import-CustomViews {
    param([string]$Path = "C:\Program Files\WindowsPowerShell\Modules\SOAP-Modules\Custom-Views")
    $CustomViewsFolder = "C:\ProgramData\Microsoft\Event Viewer\Views"
    $CustomViews = Get-ChildItem -Recurse $CustomViewsFolder
    Get-ChildItem -Recurse "$Path\*.xml" |
    Where-Object { $_.Name -notin $CustomViews } | 
    Copy-Item -Destination $CustomViewsFolder
}


function New-CustomModule {
    param(
        [Parameter(Mandatory,Position=0)][string]$Name,
        [Parameter(Mandatory,Position=1)][string]$Author,
        [Parameter(Mandatory,Position=2)][string]$Description
    )
    $Directory = "C:\Program Files\WindowsPowerShell\Modules\$Name"
    $Module = "$Directory\$Name.psm1"
    $Manifest = "$Directory\$Name.psd1"
    if (Test-Path -Path $Directory) {
        Write-Output "[x] The $Name module already exists."
    } else { 
        New-Item -ItemType Directory -Path $Directory | Out-Null
        New-Item -ItemType File -Path $Module | Out-Null
        New-ModuleManifest -Path $Manifest `
            -Author $Author `
            -RootModule "$Name.psm1" `
            -Description $Description
        if (Test-Path -Path $Module) {
            Write-Output "[+] Created the $Name module."
        }
    }
}

function Remove-CustomModule {
    param([Parameter(Mandatory)][string]$Name)
    $Module = "C:\Program Files\WindowsPowerShell\Modules\$Name"
    if (Test-Path -Path $Module) {
        Remove-Item -Path $Module -Recurse -Force
        if (-not (Test-Path -Path $Module)) {
            Write-Output "[+] Deleted the $Name module."
        }
    } else {
        Write-Output "[x] The $Name module does not exist."
    }
}

function Start-Coffee {
    while ($true) { (New-Object -ComObject Wscript.Shell).Sendkeys(' '); sleep 60 }
}
