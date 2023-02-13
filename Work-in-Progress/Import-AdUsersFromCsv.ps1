function Import-AdUsersFromCsv {
  $Password = ConvertTo-SecureString -String '1qaz2wsx!QAZ@WSX' -AsPlainText -Force
  Import-Csv -Path .\users.csv |
  ForEach-Object {
      $Name = $_.LastName + ', ' + $_.FirstName
      $SamAccountName = ($_.FirstName + '.' + $_.LastName).ToLower()
      $UserPrincipalName = $SamAccountName + '@' + (Get-AdDomain).Forest
      $Description = $_.Description
      $ExpirationDate = Get-Date -Date 'October 31 2022'
      New-AdUser `
          -Name $Name `
          -DisplayName $Name `
          -GivenName $_.FirstName `
          -Surname $_.LastName `
          -SamAccountName $SamAccountName `
          -UserPrincipalName $UserPrincipalName `
          -Description $Description `
          -ChangePasswordAtLogon $true `
          -AccountExpirationDate $ExpirationDate `
          -Enabled $true `
          -Path "OU=Users,$(Get-ADDomain).DistinguishedName" `
          -AccountPassword $Password
  }
}