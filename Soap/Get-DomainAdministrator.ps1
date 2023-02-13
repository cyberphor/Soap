function Get-DomainAdministrator {
  Get-AdGroupMember -Identity "Domain Admins" |
  Select-Object -Property Name,SamAccountName,Sid |
  Format-Table -AutoSize
}