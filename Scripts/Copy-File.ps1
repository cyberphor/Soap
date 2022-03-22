Param(
    [string]$Computers,
    [string]$File
)

$Destination = '\\$_\C$\Users\Public\Desktop'

Get-content $Computers |
ForEach-Object {
	$Computer = $_
	If (Test-Connection -Count 2 -ComputerName $Computer -Quiet) {
		Write-Output "[+] $Computer is online."
		Try {
			ForEach-Object {
				Write-Output "[+] Copying $File to $Computer.`n"
				Copy-Item -Path $file -Destination $Destination
			}
		} Catch { "[x] Failed to copy $File to $Computer.`n" }
	} Else { Write-Output "[x] $Computer appears to be offline.`n" }
}
