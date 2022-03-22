Param([string]$Computers)

Get-Content $Computers |
ForEach-Object {
	$Computer = $_
	Write-Output "---------------------------------------"
	If (Test-Connection -ComputerName $Computer -Count 2 -Quiet) {
		$Serial = Invoke-Command -ComputerName $Computer -ScriptBlock {
			Get-WmiObject -Class Win32_BIOS | Select -ExpandProperty SerialNumber
			}
		$CurrentUser = Invoke-Command -ComputerName $Computer -ScriptBlock {
			Get-WmiObject -Class Win32_ComputerSystem | Select -ExpandProperty UserName
			}
		Write-Output "[+] $Computer | $Serial | $CurrentUser"
	} Else { Write-Output "[x] Failed to ping $Computer." }
} | Tee -Append "./ComputerInfo_$(Get-Date -Format yyyymmdd_HHMMss)"
