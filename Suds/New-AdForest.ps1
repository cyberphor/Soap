function New-AdForest {
  Param(
      [Parameter(Mandatory)][string]$DomainName,
      [securestring]$SafeModeAdministratorPassword = $(ConvertTo-SecureString -AsPlainText -Force "1qaz2wsx!QAZ@WSX")
  )
  Install-WindowsFeature DNS, AD-Domain-Services -IncludeManagementTools
  $Parameters = @{
      InstallDns                    = $True
      DomainName                    = $DomainName
      SafeModeAdministratorPassword = $SafeModeAdministratorPassword
      NoRebootOnCompletion          = $True
      Force                         = $True
  }
  Install-ADDSForest @Parameters
}