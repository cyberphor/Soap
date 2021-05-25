$Credential = Get-Credential
$Computers = ""

$Computers | 
foreach {
    $Session = New-PSSession -ComputerName $_ -Credential $Credential -ErrorAction Ignore
    Copy-Item .\Start-Scare.ps1 -Destination "C:\" -ToSession $Session -ErrorAction Ignore
}

Invoke-Command -ComputerName $Computers -ErrorAction Ignore -FilePath ./Start-RollingReboot.ps1
