Param(
    [switch]$BlockIp,
    [switch]$EvilProcess,
    [switch]$SuspiciousFile,
    [switch]$UnblockIp,
    [string]$SearchBase = (Get-AdDomain).DistinguishedName
)

if ($SuspiciousFile) {
    $Script = ".\Get-SuspiciousFile.ps1"
    $ArgumentList = ""
    $Output = "Hostname", "Username", "Model", "SerialNumber", "FilePath", "Sha256Hash"
} elseif ($EvilProcess) {
    $Script = ".\Stop-EvilProcess.ps1"
    $ArgumentList = ""
    $Output = "Hostname", "Username", "Model", "SerialNumber"
} else {
    exit
}

$Computers = Get-AdComputer -Filter * -SearchBase $SearchBase | Select-Object -ExpandProperty Name
Invoke-Command -ComputerName $Computers -ErrorAction Ignore -FilePath $Script -ArgumentList $ArgumentList |
Select $Output
