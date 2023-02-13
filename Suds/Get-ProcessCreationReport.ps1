function Get-ProcessCreationReport {
  <#
      .SYNOPSIS
      Searches the Windows "Security" Event log for commands defined in a blacklist and sends an email when a match is found. 
      
      .DESCRIPTION
      This script will automatically create a file called "SentItems.log" to keep track of what logs have already been emailed (using the Record Id field/value). 
      
      .INPUTS
      None. You cannot pipe objects to this script.
      
      .OUTPUTS
      An email.
      
      .EXAMPLE 
      Get-ProcessCreationReport.ps1 -BlacklistFile ".\command-blacklist.txt" -EmailServer "smtp.gmail.com" -EmailServerPort 587 -EmailAddressSource "DrSpockTheChandelier@gmail.com" -EmailPassword "iHaveABadFeelingAboutThis2022!" -EmailAddressDestination "DrSpockTheChandelier@gmail.com" 
  
      .NOTES
      If you are going to use Gmail, this is what you need to use (as of 17 MAR 22):
      - EmailServer = smtp.gmail.com
      - EmailServerPort = 587
      - EmailAddressSource = YourEmailAddress@gmail.com
      - EmailAddressDestination = AnyEmailAddress@AnyDomain.com
      - EmailPassword = iHaveABadFeelingAboutThis2022!
  
      Also, consider reading this:
      - https://myaccount.google.com/lesssecureapps
  #>
  Param(
      [Parameter(Mandatory)][string]$BlacklistFile,
      [Parameter(Mandatory)][string]$EmailServer,
      [Parameter(Mandatory)][int]$EmailServerPort,
      [Parameter(Mandatory)][string]$EmailAddressSource,
      [Parameter(Mandatory)][string]$EmailPassword,
      [Parameter(Mandatory)][string]$EmailAddressDestination,
      [string]$SentItemsLog = ".\SentItems.log"           
  )
  $UserId = [Security.Principal.WindowsIdentity]::GetCurrent()
  $AdminId = [Security.Principal.WindowsBuiltInRole]::Administrator
  $CurrentUser = New-Object Security.Principal.WindowsPrincipal($UserId)
  $RunningAsAdmin = $CurrentUser.IsInRole($AdminId)
  if (-not $RunningAsAdmin) { 
      Write-Error "This script requires administrator privileges."
      break
  }
  # get the command blacklist
  # - commands in your blacklist must include the full-path
  #   - ex: C:\Windows\System32\whoami.exe
  $Blacklist = Get-Content -Path $BlacklistFile
  if (Test-Path $SentItemsLog) {
      # check if the script log exists
      # - save its contents to a variable
      $SentItems = Get-Content -Path $SentItemsLog
  } else {
      # otherwise, create a script log
      # - this is important so you are not sending the same record multiple times
      New-Item -ItemType File -Path $SentItemsLog | Out-Null
  }
  # define the search criteria
  $FilterHashTable = @{
      LogName = "Security"
      Id = 4688
      StartTime = $(Get-Date).AddDays(-1)    
  }
  # cycle through events matching the criteria above
  # - return the first event that contains a command on the blacklist
  $Event = Get-WinEvent -FilterHashtable $FilterHashTable |
      Where-Object { 
          ($Blacklist -contains $_.Properties[5].Value) -and 
          ($SentItems -notcontains $_.RecordId)    
      } | 
      Select-Object * -First 1
  # if there is an event meeting the criteria defined, send an email
  if ($Event) {
      # assign important fields to separate variables for readability
      $EventId = $Event.Id
      $Source = $Event.ProviderName
      $MachineName = $Event.MachineName
      $Message = $Event.Message
      # define values required to send an email via PowerShell
      $EmailClient = New-Object Net.Mail.SmtpClient($EmailServer, $EmailServerPort)
      $Subject = "Alert from $MachineName"
      $Body = "
          EventID: $EventId `r
          Source: $Source `r `
          MachineName: $MachineName `r
          Message: $Message `r
      "
      $EmailClient.EnableSsl = $true
      $EmailClient.Credentials = New-Object System.Net.NetworkCredential($EmailAddressSource, $EmailPassword)
      $EmailClient.Send($EmailAddressSource, $EmailAddressDestination, $Subject, $Body)
      Add-Content -Value $Event.RecordId -Path $SentItemsLog
  }
}