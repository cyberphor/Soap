function New-AdDomainAdmin {
  Param(
      [Parameter(Mandatory)][string]$FirstName,
      [Parameter(Mandatory)][string]$LastName,
      [securestring]$Password = $(ConvertTo-SecureString -String '1qaz2wsx!QAZ@WSX' -AsPlainText -Force)
  )
  $Name = "$LastName, $FirstName (DA)"
  $SamAccountName = ("$FirstName.$LastName.da").ToLower()
  $AccountExpirationDate = (Get-Date).AddYears(1)
  New-ADUser `
      -GivenName $FirstName `
      -Surname $LastName `
      -Name $Name `
      -DisplayName $Name `
      -SamAccountName $SamAccountName `
      -AccountPassword $Password `
      -AccountExpirationDate $AccountExpirationDate `
      -ChangePasswordAtLogon $true `
      -Enabled $true
  Add-ADGroupMember -Identity "Domain Admins" -Members $SamAccountName
}