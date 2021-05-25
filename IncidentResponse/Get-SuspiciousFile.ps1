function Get-SuspiciousFile {
  $SearchPath = "C:\"
  $File = Get-ChildItem $SearchPath -Recurse -Name *foo.txt | Select-Object -First 1
  $FilePath = $SearchPath + $File
    
  if ($File) {
    $Username = (Get-WmiObject -Class Win32_NetworkLoginProfile | 
      Where-Object { $_.Name -notlike "*admin*" -and $_.Name -notlike "*service*" } |
      Sort-Object -Property LastLogon -Descending |
      Select-Object -First 1 -ExpandProperty Name).Split("\")[1]
    $Model = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model
    $SerialNumber = Get-WmiObject -Class Win32_BIOS | Select-Object -ExpandProperty SerialNumber
    $Sha256Hash = Get-FileHash $FilePath | Select-Object -ExpandProperty Hash
    
    $ComputerInformation = New-Object psobject
    Add-Member -InputObject $ComputerInformation -MemberType NoteProperty -Name Hostname -Value $Hostname
    Add-Member -InputObject $ComputerInformation -MemberType NoteProperty -Name Username -Value $Username
    Add-Member -InputObject $ComputerInformation -MemberType NoteProperty -Name Model -Value $Model
    Add-Member -InputObject $ComputerInformation -MemberType NoteProperty -Name SerialNumber -Value $SerialNumber
    Add-Member -InputObject $ComputerInformation -MemberType NoteProperty -Name FilePath -Value $FilePath
    Add-Member -InputObject $ComputerInformation -MemberType NoteProperty -Name Sha256Hash -Value $Sha256Hash
    $ComputerInformation
  }
}

Get-SuspiciousFile
