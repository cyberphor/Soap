<#
.SYNOPSIS
    Downloads code repositories from GitHub.
.EXAMPLE
    ./Get-SupplyDrop.ps1 -From cyberphor
.INPUTS
    GitHub username.
.OUTPUTS
    GitHub code repository.
.LINK
    https://www.yoursecurity.tech
.NOTES
    File name: Get-SupplyDrop.ps1
    Version: 3.0
    Author: Victor Fernandez III
    Creation Date: Saturday, January 25, 2020
#>

Param([Parameter(Mandatory=$true)][string]$From)

Clear-Host
$ErrorActionPreference = 'Stop'

try {
    Write-Output "`n [-] Checking DNS... `n"
    $Domain = 'github.com'
    $ResolvingDomain = Resolve-DnsName -Name $Domain -Type A -QuickTimeout
    $URL = "https://$Domain/$From"
    if (-not $ResolvingDomain) { Throw "Failed to complete a DNS request for $Domain." }
    
    Clear-Host
    Write-Output "`n [+] $From's Github repositories: "
    $GithubProfile = Invoke-WebRequest -UseBasicParsing $URL
    $GithubProfile -Split "`n" | 
        Select-String '<span class="repo" title="' |
        ForEach-Object {
            $Repo = $_.ToString().Split('>')[1].Split('<')[0]
            Write-Output " - $Repo"
        }
    $Repository = Read-Host -Prompt "`n [!] Which one would you like to download?"
    $Branch = 'master'
    $URI = "$URL/$Repository/archive/$Branch.zip"

    if (Invoke-WebRequest -Method Head -Uri $URI) {
        Clear-Host
        $DropZone = $pwd.ToString() + '\' + $Repository
        $DropZoneIsOccupied = Test-Path $DropZone
        if ($DropZoneIsOccupied) { Throw 'You may have already downloaded it.' }
        else {
            Clear-Host
            $SupplyDrop = $DropZone + '\' + $Repository + '-' + $Branch + '\'
            $SupplyDropZipped = $DropZone + '.zip'
    
            Write-Output "`n [-] Downloading... `n"
            Invoke-WebRequest -Uri $URI -OutFile $SupplyDropZipped
            Expand-Archive $SupplyDropZipped
            Remove-Item $SupplyDropZipped -Recurse 
            Move-Item ($SupplyDrop + "*") -Destination $DropZone
            Remove-Item -Path $SupplyDrop -Recurse
            Clear-Host
            Write-Output "`n [+] Success!"
            Get-ChildItem $DropZone
        }
    }
} catch { 
    Clear-Host
    Write-Output "`n [x] $_ `n" 
}
