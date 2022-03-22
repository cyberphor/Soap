$Name = 'Filebeat'
if (Get-Service $Name -ErrorAction SilentlyContinue) {
  	$Service = Get-WmiObject -Class Win32_Service -Filter "name='$Name'"
  	$Service.StopService()
 	Start-Sleep -Seconds 1
 	$Service.Delete()
 }

$Description = 'A lightweight shipper for forwarding and centralizing log data.'  
$Program = $Name.ToLower() + '.exe'
$ConfigurationFile = $Name.ToLower() + '.yml'
$Requirements = $Program, $ConfigurationFile
$InstallationFilePath = $env:ProgramData + '\' + $Name
$ConfigurationFilePath = $InstallationFilePath + '\' + $ConfigurationFile
$ServiceIsInstalled = Get-Service | Where-Object { $_.Name -like $Name }
$Binary = "`"$InstallationFilePath\$Program`""
$Arguments = " -c `"$ConfigurationFilePath`" -path.home `"$InstallationFilePath`" -path.data `"$InstallationFilePath`" -path.logs `"$InstallationFilePath\logs`""
$BinaryPathName = $Binary + $Arguments

New-Service -Name $Name -DisplayName $Name -BinaryPathName $BinaryPathName
Start-Service $Name
Get-Service $Name
