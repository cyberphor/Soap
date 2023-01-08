function ConvertFrom-Base64 {
  <#
      .SYNOPSIS
      Decodes Base64 strings. 

      .DESCRIPTION
      Decodes Base64 string objects into UTF-16 Little Endian objects.

      .INPUTS
      This function accepts piped objects.

      .OUTPUTS
      System.String.

      .EXAMPLE
      PS> "dABlAHMAdAAtAGMAbwBuAG4AZQBjAHQAaQBvAG4AIAA4AC4AOAAuADgALgA4AA==" | ConvertFrom-Base64
      test-connection 8.8.8.8

      .LINK
      https://github.com/cyberphor/Soap
  #>
  Param([Parameter(Mandatory, ValueFromPipeline)]$String)
  [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($String))
}

function ConvertTo-Base64 {
  <#
      .SYNOPSIS
      Encodes objects into Base64 strings. 

      .DESCRIPTION
      Encodes UTF-16 Little Endian objects into Base64 string objects.

      .INPUTS
      This function accepts piped objects.

      .OUTPUTS
      System.String.

      .EXAMPLE
      PS> echo "test-connection 8.8.8.8" | ConvertTo-Base64
      dABlAHMAdAAtAGMAbwBuAG4AZQBjAHQAaQBvAG4AIAA4AC4AOAAuADgALgA4AA==
      
      PS> powershell -e dABlAHMAdAAtAGMAbwBuAG4AZQBjAHQAaQBvAG4AIAA4AC4AOAAuADgALgA4AA==
      Source        Destination     IPV4Address      IPV6Address                              Bytes    Time(ms) 
      ------        -----------     -----------      -----------                              -----    -------- 
      LAPTOP-H4T... 8.8.8.8         8.8.4.4                                                   32       18       
      LAPTOP-H4T... 8.8.8.8         8.8.4.4                                                   32       22       
      LAPTOP-H4T... 8.8.8.8         8.8.4.4                                                   32       22       
      LAPTOP-H4T... 8.8.8.8         8.8.4.4                                                   32       17       
  #>
  Param([Parameter(Mandatory, ValueFromPipeline)]$String)
  $Bytes = [System.Text.Encoding]::Unicode.GetBytes($String)
  [Convert]::ToBase64String($Bytes)
}

function ConvertTo-BinaryString {
  <#
      .SYNOPSIS
      Converts the provided IP address into binary.

      .DESCRIPTION
      Outputs a string of binary digits if the provided input is a valid IP address.

      .INPUTS
      This function accepts piped objects.

      .OUTPUTS
      System.String.

      .EXAMPLE
      PS> "8.8.8.8" | ConvertTo-BinaryString
      1000000010000000100000001000

      .LINK
      https://github.com/cyberphor/Soap
  #>
  Param([parameter(Mandatory,ValueFromPipeline)][IPAddress]$IpAddress)
  $Integer = $IpAddress.Address
  $ReverseIpAddress = [IPAddress][String]$Integer
  $BinaryString = [Convert]::toString($ReverseIpAddress.Address,2)
  return $BinaryString
}

function ConvertTo-IpAddress {
  <#
      .SYNOPSIS
      Converts the provided string into an IP address.

      .DESCRIPTION
      Outputs an IP address if the provided input is a string of binary digits. 

      .INPUTS
      This function accepts piped objects.

      .OUTPUTS
      System.String.

      .EXAMPLE
      PS> ConvertTo-IpAddress -BinaryString 1000000010000000100000001000
      8.8.8.8

      .LINK
      https://github.com/cyberphor/Soap
  #>
  Param([parameter(Mandatory,ValueFromPipeline)][string]$BinaryString)
  $Integer = [System.Convert]::ToInt64($BinaryString,2).ToString()
  $IpAddress = ([System.Net.IPAddress]$Integer).IpAddressToString
  return $IpAddress
}

function Export-Gpo {
  Write-Output "`n[+] Available GPOs:"
  $AllGPOs = (Get-GPO -All).DisplayName
  $AllGPOs | ForEach-Object { Write-Output " -   $_"}
  $GPOName = Read-Host -Prompt "`n[+] Which GPO do you want exported? `n -   GPO Name"

  if ($AllGPOs -contains $GPOName) {
      $GPOBackupFolder = "$PWD\" + ($GPOName).Replace(" ", "-") + "GPO"
      $FindingGPOBackupFolder = Test-Path -Path $GPOBackupFolder
      if (-not $FindingGPOBackupFolder) {
          New-Item -Type Directory -Path $GPOBackupFolder | Out-Null
      }
      $GPOGuid = '{' + (Backup-GPO -Name $GPOName -Path $GPOBackupFolder).Id + '}'

      $OldDC = $env:COMPUTERNAME
      $OldNetBIOSName = $env:USERDOMAIN
      $OldDNSDomainName = $env:USERDNSDOMAIN

      $NewDC = 'DC1'
      $NewNetBIOSName = 'CONTOSO'
      $NewDNSDomainName = 'contoso.com'

      $Files = @(
          "$GPOBackupFolder\$GPOGuid\Backup.xml"
          "$GPOBackupFolder\$GPOGuid\bkupInfo.xml" 
          "$GPOBackupFolder\$GPOGuid\gpreport.xml"
      ) 

      $Files |
      ForEach-Object {
          Write-Output "`n[+] Scrubbing $_"
          (Get-Content -Path $_) `
          -replace $OldDC, $NewDC `
          -replace $OldDNSDomainName, $NewDNSDomainName `
          -replace $OldNetBIOSName, $NewNetBIOSName |
          Set-Content $_
          Write-Output " -   Done."
      }
  }
}

function Get-DscResourcesRequired {
  Param([string[]]$Resources = @("AuditPolicyDsc","xBitLocker","NetworkingDsc"))
  $DownloadStartTime = Get-Date
  $OutputFile = "DscResources.zip"
  Install-Module -Name $Resources -Scope CurrentUser -Force
  if (Test-Path $OutputFile) { Remove-Item $OutputFile -Force }
  $env:PSModulePath -split ';' | 
  Where-Object { $_ -like "*$env:USERNAME*" } |
  Get-ChildItem | 
  Where-Object { $_.LastWriteTime -gt $DownloadStartTime } |
  Select-Object -ExpandProperty FullName |
  Compress-Archive -DestinationPath "DscResources.zip"
}

function Get-EventViewer {
  # create a COM object for Excel
  $Excel = New-Object -ComObject Excel.Application

  # create a workbook and then add two worksheets to it
  $Workbook = $Excel.Workbooks.Add()
  $Tab2 = $Workbook.Worksheets.Add()
  $Tab3 = $Workbook.Worksheets.Add()

  function Get-SuccessfulLogonEvents {
      # rename the first worksheet 
      $Workbook.Worksheets.Item(1).Name = "SuccessfulLogon"

      # define column headers using the first row
      $Workbook.Worksheets.Item("SuccessfulLogon").Cells.Item(1,1) = "TimeCreated"
      $Workbook.Worksheets.Item("SuccessfulLogon").Cells.Item(1,2) = "RecordId"
      $Workbook.Worksheets.Item("SuccessfulLogon").Cells.Item(1,3) = "UserName"
      $Workbook.Worksheets.Item("SuccessfulLogon").Cells.Item(1,4) = "LogonType"
  
      # define where to begin adding data (by row and column)
      $rTimeCreated, $cTimeCreated = 2,1
      $rRecordId, $cRecordId = 2,2
      $rUserName, $cUserName = 2,3
      $rLogonType, $cLogonType = 2,4

      # define what Windows Event criteria must match 
      $FilterHashTable = @{
          LogName = "Security"
          Id = 4624
          StartTime = (Get-Date).AddDays(-1)
      }

      # cycle through the Windows Events that match the criteria above
      Get-WinEvent -FilterHashtable $FilterHashTable |
      Read-WinEvent |
      Select-Object -Property TimeCreated,EventRecordId,TargetUserName,LogonType |
      Where-Object { 
          $_.TargetUserName -ne "SYSTEM" 
      } |
      ForEach-Object {
          [System.GC]::Collect()
          # fill-in the current row
          $Workbook.Worksheets.Item("SuccessfulLogon").Cells.Item($rTimeCreated, $cTimeCreated) = $_.TimeCreated
          $Workbook.Worksheets.Item("SuccessfulLogon").Cells.Item($rRecordId, $cRecordId) = $_.EventRecordId
          $Workbook.Worksheets.Item("SuccessfulLogon").Cells.Item($rUserName, $cUserName) = $_.TargetUserName
          $Workbook.Worksheets.Item("SuccessfulLogon").Cells.Item($rLogonType, $cLogonType) = $_.LogonType

          # move-on to the next row
          $rTimeCreated++
          $rRecordId++
          $rUserName++
          $rLogonType++
      }
  }

  function Get-ProcessCreationEvents {
      # rename the second worksheet 
      $Workbook.Worksheets.Item(2).Name = "ProcessCreation"

      # define column headers using the first row
      $Workbook.Worksheets.Item("ProcessCreation").Cells.Item(1,1) = "TimeCreated"
      $Workbook.Worksheets.Item("ProcessCreation").Cells.Item(1,2) = "RecordId"
      $Workbook.Worksheets.Item("ProcessCreation").Cells.Item(1,3) = "UserName"
      $Workbook.Worksheets.Item("ProcessCreation").Cells.Item(1,4) = "ParentProcessName"
      $Workbook.Worksheets.Item("ProcessCreation").Cells.Item(1,5) = "NewProcessName"
      $Workbook.Worksheets.Item("ProcessCreation").Cells.Item(1,6) = "CommandLine"
  
      # define where to begin adding data (by row and column)
      $rTimeCreated, $cTimeCreated = 2,1
      $rRecordId, $cRecordId = 2,2
      $rUserName, $cUserName = 2,3
      $rParentProcessName, $cParentProcessName = 2,4
      $rNewProcessName, $cNewProcessName = 2,5
      $rCommandLine, $cCommandLine = 2,6

      # define what Windows Event criteria must match 
      $FilterHashTable = @{
          LogName = "Security"
          Id = 4688
          StartTime = (Get-Date).AddDays(-1)

      }
      # cycle through the Windows Events that match the criteria above
      Get-WinEvent -FilterHashtable $FilterHashTable |
      Read-WinEvent |
      Select-Object -Property TimeCreated,EventRecordId,TargetUserName,ParentProcessName,NewProcessName,CommandLine |
      Where-Object { 
          ($_.TargetUserName -ne "-") -and `
          ($_.TargetUserName -notlike "*$") -and `
          ($_.TargetUserName -ne "LOCAL SERVICE")
      } |
      ForEach-Object {
          [System.GC]::Collect()
          # fill-in the current row
          $Workbook.Worksheets.Item("ProcessCreation").Cells.Item($rTimeCreated, $cTimeCreated) = $_.TimeCreated
          $Workbook.Worksheets.Item("ProcessCreation").Cells.Item($rRecordId, $cRecordId) = $_.EventRecordId
          $Workbook.Worksheets.Item("ProcessCreation").Cells.Item($rUserName, $cUserName) = $_.TargetUserName
          $Workbook.Worksheets.Item("ProcessCreation").Cells.Item($rParentProcessName, $cParentProcessName) = $_.ParentProcessName
          $Workbook.Worksheets.Item("ProcessCreation").Cells.Item($rNewProcessName, $cNewProcessName) = $_.NewProcessName
          $Workbook.Worksheets.Item("ProcessCreation").Cells.Item($rCommandLine, $cCommandLine) = $_.CommandLine

          # move-on to the next row
          $rTimeCreated++
          $rRecordId++
          $rUserName++
          $rParentProcessName++
          $rNewProcessName++
          $rCommandLine++
      }
  }

  function Get-PowerShellEvents {
      # rename the third worksheet 
      $Workbook.Worksheets.Item(3).Name = "PowerShell"

      # define column headers using the first row
      $Workbook.Worksheets.Item("PowerShell").Cells.Item(1,1) = "TimeCreated"
      $Workbook.Worksheets.Item("PowerShell").Cells.Item(1,2) = "RecordId"
      $Workbook.Worksheets.Item("PowerShell").Cells.Item(1,3) = "Sid"
      $Workbook.Worksheets.Item("PowerShell").Cells.Item(1,4) = "ScriptBlockText"
  
      # define where to begin adding data (by row and column)
      $rTimeCreated, $cTimeCreated = 2,1
      $rRecordId, $cRecordId = 2,2
      $rSid, $cSid = 2,3
      $rScriptBlockText, $cScriptBlockText = 2,4

      # define what Windows Event criteria must match 
      $FilterHashTable = @{
          LogName = "Microsoft-Windows-PowerShell/Operational"
          Id = 4104
          StartTime = (Get-Date).AddDays(-1)
      }

      # cycle through the Windows Events that match the criteria above
      Get-WinEvent -FilterHashtable $FilterHashTable |
      Read-WinEvent |
      Select-Object -Property TimeCreated,EventRecordId,@{N="Sid";E={$_.Security.UserId}},ScriptBlockText |
      Where-Object {
          ($_.Sid -ne "S-1-5-18") -and
          ($_.ScriptBlockText -ne "prompt")
      } |
      ForEach-Object {
          [System.GC]::Collect()
          # fill-in the current row
          $Workbook.Worksheets.Item("PowerShell").Cells.Item($rTimeCreated, $cTimeCreated) = $_.TimeCreated
          $Workbook.Worksheets.Item("PowerShell").Cells.Item($rRecordId, $cRecordId) = $_.EventRecordId
          $Workbook.Worksheets.Item("PowerShell").Cells.Item($rSid, $cSid) = $_.Sid
          $Workbook.Worksheets.Item("PowerShell").Cells.Item($rScriptBlockText, $cScriptBlockText) = $_.ScriptBlockText

          # move-on to the next row
          $rTimeCreated++
          $rRecordId++
          $rSid++
          $rScriptBlockText++
      }
  }

  $Path = $env:USERPROFILE + "\Desktop\Events-" + $(Get-Date -Format yyyy-MM-dd_hhmm) +".xlsx"
  $Workbook.SaveAs($Path,51)

  Get-SuccessfulLogonEvents
  $Workbook.Worksheets.Item("SuccessfulLogon").UsedRange.Columns.Autofit() | Out-Null

  Get-ProcessCreationEvents
  $Workbook.Worksheets.Item("ProcessCreation").UsedRange.Columns.Autofit() | Out-Null
  $Workbook.Save()

  Get-PowerShellEvents
  $Workbook.Worksheets.Item("PowerShell").UsedRange.Columns.Autofit() | Out-Null
  $Workbook.Save()

  $Excel.Quit()
  Invoke-Item -Path $Path
}

function Get-IpAddressRange {
  <#
      .SYNOPSIS
      Given a network ID in CIDR notation, returns an array of IPv4 address strings.

      .DESCRIPTION
      Given a network ID in CIDR notation, returns an array of IPv4 address strings.

      .PARAMETER Network
      Specifies the network ID in CIDR notation.

      .INPUTS
      None. You cannot pipe objects to Get-IpAddressRange.

      .OUTPUTS
      System.Array. Get-IpAddressRange returns an array of IPv4 address strings.

      .EXAMPLE
      Get-IpAddressRange -Network 192.168.2.0/30
      192.168.2.1
      192.168.2.2

      .EXAMPLE
      Get-IpAddressRange -Network 192.168.2.0/30, 192.168.3.0/30
      192.168.2.1
      192.168.2.2
      192.168.3.1
      192.168.3.2

      .EXAMPLE
      Get-IpAddressRange -Network 192.168.2.1/32
      192.168.2.1

      .LINK
      https://github.com/cyberphor/soap

      .NOTES
      https://community.spiceworks.com/topic/649706-question-on-splitting-a-string-in-powershell
      https://devblogs.microsoft.com/scripting/use-powershell-to-easily-convert-decimal-to-binary-and-back/
      https://stackoverflow.com/questions/28460208/what-is-the-idiomatic-way-to-slice-an-array-relative-to-both-of-its-ends
      https://community.idera.com/database-tools/powershell/powertips/b/tips/posts/converting-binary-data-to-ip-address-and-vice-versa
  #>
  Param([Parameter(Mandatory)][string[]]$Network)
  $IpAddressRange = @()
  $Network |
  foreach {
      if ($_.Contains('/')) {
          $NetworkId = $_.Split('/')[0]
          $SubnetMask = $_.Split('/')[1]
          if ([ipaddress]$NetworkId -and ($SubnetMask -eq 32)) {
              $IpAddressRange += $NetworkId          
          } elseif ([ipaddress]$NetworkId -and ($SubnetMask -le 32)) {
              $Wildcard = 32 - $SubnetMask
              $NetworkIdBinary = ConvertTo-BinaryString $NetworkId
              $NetworkIdIpAddressBinary = $NetworkIdBinary.SubString(0,$SubnetMask) + ('0' * $Wildcard)
              $BroadcastIpAddressBinary = $NetworkIdBinary.SubString(0,$SubnetMask) + ('1' * $Wildcard)
              $NetworkIdIpAddress = ConvertTo-IpAddress $NetworkIdIpAddressBinary
              $BroadcastIpAddress = ConvertTo-IpAddress $BroadcastIpAddressBinary
              $NetworkIdInt32 = [convert]::ToInt32($NetworkIdIpAddressBinary,2)
              $BroadcastIdInt32 = [convert]::ToInt32($BroadcastIpAddressBinary,2)
              $NetworkIdInt32..$BroadcastIdInt32 | 
              foreach {
                  $BinaryString = [convert]::ToString($_,2)
                  $Address = ConvertTo-IpAddress $BinaryString
                  $IpAddressRange += $Address
              }            
          }
      }
  }
  return $IpAddressRange
}

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

function Get-SerialNumberAndCurrentUser {
  Param([string[]]$ComputerName)
  Invoke-Command -ComputerName $ComputerName -ScriptBlock {
      Get-WmiObject -Class Win32_Bios | Select-Object -ExpandProperty SerialNumber
      Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName
  }
}

function Get-Stig {
  <#
      .SYNOPSIS
      Returns STIG rules as PowerShell objects.
              
      .DESCRIPTION
      Returns Security Technical Implementation Guide (STIG) rules as PowerShell objects after reading an Extensible Configuration Checklist Description Format (XCCDF) document.

      .INPUTS
      None. You cannot pipe objects to Get-Stig.

      .OUTPUTS
      PSCustomObject.

      .EXAMPLE
      Get-Stig -Path 'U_MS_Windows_10_STIG_V2R3_Manual-xccdf.xml'

      .LINK
      https://gist.github.com/entelechyIT
  #>
  Param([Parameter(Mandatory)]$Path)
  if (Test-Path $Path) {
      [xml]$XCCDFdocument = Get-Content -Path $Path
      if ($XCCDFdocument.Benchmark.xmlns -like 'http://checklists.nist.gov/xccdf/*') {
          $Stig = @()
          $XCCDFdocument.Benchmark.Group.Rule |
          ForEach-Object {
              $Rule = New-Object -TypeName PSObject -Property ([ordered]@{
                  RuleID    = $PSItem. id
                  RuleTitle = $PSItem.title 
                  Severity = $PSItem.severity
                  VulnerabilityDetails = $($($($PSItem.description) -split '</VulnDiscussion>')[0] -replace '<VulnDiscussion>', '')
                  Check = $PSItem.check.'check-content'
                  Fix = $PSItem.fixtext.'#text'
                  ControlIdentifier = $PSItem.ident.'#text'
                  Control = $null 
              })
              $Stig += $Rule
          }
          return $Stig
      } 
      Write-Error 'The file provided is not a XCCDF document.'
  }
}

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

function Install-RSAT {
  Get-WindowsCapability -Name RSAT* -Online | 
  Add-WindowsCapability -Online
}

function Install-Sysmon {
  Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
  Expand-Archive -Path "Sysmon.zip" -DestinationPath "C:\Program Files\Sysmon" 
  Remove-Item -Path "Sysmon.zip" -Recurse
  Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Program Files\Sysmon\config.xml"
  Invoke-Expression "C:\'Program Files'\Sysmon\Sysmon64.exe -accepteula -i C:\'Program Files'\Sysmon\config.xml"
}

function Invoke-SecurityBaseline {
  # V-220726: Data Execution Prevention (DEP) must be configured to at least OptOut.
  bcdedit /set "{current}" nx OptOut

  # V-220748
  auditpol /set /subcategory:"Credential Validation" /failure:enable

  # V-220749
  auditpol /set /subcategory:"Credential Validation" /success:enable

  # V-220750
  auditpol /set /subcategory:"Security Group Management" /success:enable

  # V-220751
  auditpol /set /subcategory:"User Account Management" /failure:enable

  # V-220752
  auditpol /set /subcategory:"User Account Management" /success:enable

  # V-220753
  auditpol /set /subcategory:"Plug and Play Events" /success:enable

  # V-220754
  auditpol /set /subcategory:"Process Creation" /success:enable

  # V-220755
  auditpol /set /subcategory:"Account Lockout" /failure:enable

  # V-220756
  auditpol /set /subcategory:"Group Membership" /success:enable

  # V-220757
  auditpol /set /subcategory:"Logoff" /success:enable

  # V-220758
  auditpol /set /subcategory:"Logon" /failure:enable

  # V-220759
  auditpol /set /subcategory:"Logon" /success:enable

  # V-220760
  auditpol /set /subcategory:"Special Logon" /success:enable

  # V-220761
  auditpol /set /subcategory:"File Share" /failure:enable

  # V-220762
  auditpol /set /subcategory:"File Share" /success:enable

  # V-220763
  auditpol /set /subcategory:"Other Object Access Events" /success:enable

  # V-220764
  auditpol /set /subcategory:"Other Object Access Events" /failure:enable

  # V-220765
  auditpol /set /subcategory:"Removable Storage" /failure:enable

  # V-220766
  auditpol /set /subcategory:"Removable Storage" /success:enable

  # V-220767
  auditpol /set /subcategory:"Audit Policy Change" /success:enable

  # V-220768
  auditpol /set /subcategory:"Authentication Policy Change" /success:enable

  # V-220769
  auditpol /set /subcategory:"Authorization Policy Change" /success:enable

  # V-220770
  auditpol /set /subcategory:"Sensitive Privilege Use" /failure:enable

  # V-220771
  auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable

  # V-220772
  auditpol /set /subcategory:"IPSec Driver" /failure:enable

  # V-220773
  auditpol /set /subcategory:"Other System Events" /success:enable

  # V-220774
  auditpol /set /subcategory:"Other System Events" /failure:enable

  # V-220775
  auditpol /set /subcategory:"Security State Change" /success:enable

  # V-220776
  auditpol /set /subcategory:"Security System Extension" /success:enable

  # V-220777
  auditpol /set /subcategory:"System Integrity" /failure:enable

  # V-220778
  auditpol /set /subcategory:"System Integrity" /success:enable

  # V-220779: the Application event log size must be configured to 32768 KB or greater
  wevtutil sl "Application" /ms:32768000

  # V-220780: the Security event log size must be configured to 1024000 KB or greater
  wevtutil sl "Security" /ms:1024000000

  # V-220781: the System event log size must be configured to 32768 KB or greater
  wevtutil sl "System" /ms:32768000

  # V-220785
  auditpol /set /subcategory:"Other Policy Change Events" /success:enable

  # V-220786
  auditpol /set /subcategory:"Other Policy Change Events" /failure:enable

  # V-220787
  auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable

  # V-220787
  auditpol /set /subcategory:"Other Logon/Logoff Events" /failure:enable

  # V-220789
  auditpol /set /subcategory:"Detailed File Share" /success:enable

  # V-220790
  auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable

  # V-220791
  auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /failure:enable

  # V-220809: Command line data must be included in process creation events.
  $Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
  $Name = "ProcessCreationIncludeCmdLine_Enabled"
  $PropertyType = "DWORD"
  $Value = 1
  New-Item -Path $Path
  New-ItemProperty -Path $Path -Name $Name -PropertyType $PropertyType -Value $Value -Force

  # V-220823: Solicited Remote Assistance must not be allowed.
  $Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
  $Name = "fAllowToGetHelp"
  $PropertyType = "DWORD"
  $Value = 0 
  New-Item -Path $Path
  New-ItemProperty -Path $Path -Name $Name -PropertyType $PropertyType -Value $Value -Force

  # V-220827: Autoplay must be turned off for non-volume devices.
  $Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\"
  $Name = "NoAutoplayfornonVolume"
  $PropertyType = "DWORD"
  $Value = 1
  New-Item -Path $Path
  New-ItemProperty -Path $Path -Name $Name -PropertyType $PropertyType -Value $Value -Force

  # V-220828: The default autorun behavior must be configured to prevent autorun commands.
  $Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\"
  $Name = "NoAutorun"
  $PropertyType = "DWORD"
  $Value = 1
  New-Item -Path $Path
  New-ItemProperty -Path $Path -Name $Name -PropertyType $PropertyType -Value $Value -Force

  # V-220829: Autoplay must be disabled for all drives.
  $Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\"
  $Name = "NoDriveTypeAutoRun"
  $PropertyType = "DWORD"
  $Value = 255
  New-Item -Path $Path
  New-ItemProperty -Path $Path -Name $Name -PropertyType $PropertyType -Value $Value -Force

  # V-220857: The Windows Installer Always install with elevated privileges must be disabled.
  $Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\"
  $Name = "AlwaysInstallElevated"
  $PropertyType = "DWORD"
  $Value = 0
  New-Item -Path $Path
  New-ItemProperty -Path $Path -Name $Name -PropertyType $PropertyType -Value $Value -Force

  # V-220860: PowerShell script block logging must be enabled on Windows 10.
  $Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\"
  $Name = "EnableScriptBlockLogging"
  $PropertyType = "DWORD"
  $Value = 1
  New-Item -Path $Path -Force
  New-ItemProperty -Path $Path -Name $Name -PropertyType $PropertyType -Value $Value -Force

  # V-220862: The Windows Remote Management (WinRM) client must not use Basic authentication.
  $Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\"
  $Name = "AllowBasic"
  $PropertyType = "DWORD"
  $Value = 0
  New-Item -Path $Path
  New-ItemProperty -Path $Path -Name $Name -PropertyType $PropertyType -Value $Value -Force

  # V-220865: The Windows Remote Management (WinRM) service must not use Basic authentication.
  $Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\"
  $Name = "AllowBasic"
  $PropertyType = "DWORD"
  $Value = 0
  New-Item -Path $Path
  New-ItemProperty -Path $Path -Name $Name -PropertyType $PropertyType -Value $Value -Force

  # V-220913: Audit policy using subcategories must be enabled
  $Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
  $Name = "SCENoApplyLegacyAuditPolicy"
  $PropertyType = "DWORD"
  $Value = 1
  New-Item -Path $Path
  New-ItemProperty -Path $Path -Name $Name -PropertyType $PropertyType -Value $Value -Force

  # V-220930: Anonymous enumeration of shares must be restricted.
  $Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
  $Name = "RestrictAnonymous"
  $PropertyType = "DWORD"
  $Value = 1
  New-Item -Path $Path
  New-ItemProperty -Path $Path -Name $Name -PropertyType $PropertyType -Value $Value -Force

  # V-220938: The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM.
  $Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
  $Name = "LmCompatibilityLevel"
  $PropertyType = "DWORD"
  $Value = 5
  New-Item -Path $Path
  New-ItemProperty -Path $Path -Name $Name -PropertyType $PropertyType -Value $Value -Force

  # V-220978: the Manage auditing and security log user right must only be assigned to the Administrators group.
  $SecurityTemplate = @"
      [Unicode]
      Unicode=yes
      [Registry Values]
      [Privilege Rights]
      SeSecurityPrivilege = *S-1-5-32-544
      [Version]
      signature=`"`$CHICAGO`$`"
      Revision=1
"@
  $FileName = "V-220978.inf"
  if (Test-Path $FileName) {
      Remove-Item $FileName
      New-Item -ItemType File -Name $FileName | Out-Null
  }
  Add-Content -Value $SecurityTemplate -Path $FileName 
  secedit /configure /db secedit.sdb /cfg $FileName
  Remove-Item "secedit.sdb"
  Remove-Item $FileName

  # V-250318: PowerShell Transcription must be enabled on Windows 10.
  $Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
  $Name = "EnableTranscripting"
  $PropertyType = "DWORD"
  $Value = 1
  New-Item -Path $Path -Force
  New-ItemProperty -Path $Path -Name $Name -PropertyType $PropertyType -Value $Value -Force

  # Reboot
  shutdown /r /t 15 /c "Rebooting in 15 seconds."
}

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


function New-GpoWallpaper {
  Param(
      [Parameter(Mandatory)]$InputFile,
      [Parameter(Mandatory)]$Server
  )
  # create a SMB share on the server
  $Session = New-PSSession -ComputerName $Server
  Invoke-Command -Session $Session -ScriptBlock {
      New-Item -ItemType Directory -Path "C:\Wallpaper"
      New-SmbShare -Name "Wallpaper" -Path "C:\Wallpaper" -FullAccess "Administrators" -ReadAccess "Everyone"
  }
  # copy the wallpaper to the SMB share
  Copy-Item -ToSession $Session -Path $InputFile -Destination "C:\Wallpaper\Wallpaper.jpg"
  # create the GPO 
  $WallpaperPath = "\\$Server\Wallpaper\Wallpaper.jpg"
  $Key = "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System"
  New-GPO -Name "Wallpaper" -Comment "Sets the wallpaper." -ErrorAction Stop
  Set-GPRegistryValue -Name "Wallpaper" -Key $Key -ValueName "Wallpaper" -Value $WallpaperPath -Type "String"
  Set-GPRegistryValue -Name "Wallpaper" -Key $Key -ValueName "WallpaperStyle" -Value "0" -Type "String"
  New-GPLink -Name "Wallpaper" -Target  $(Get-ADDomain -Current LocalComputer).DistinguishedName   
}

function Remove-StaleDnsRecord {
  <#
      .LINK
      https://adamtheautomator.com/powershell-dns/
  #>
  $Domain = (Get-AdDomain).Forest
  $30DaysAgo = (Get-Date).AddDays(-30)
  Get-DnsServerResourceRecord -Zone $Domain -RRType A | 
  Where-Object { $_.TimeStamp -le $30DaysAgo } | 
  Remove-DnsServerResourceRecord -ZoneName $Domain -Force
}


function Start-AdBackup {
  Param(
      [Parameter(Mandatory)][string]$ComputerName,
      [string]$Share = "Backups",
      [string]$Prefix = "AdBackup"
  )
  $BackupFeature = (Install-WindowsFeature -Name Windows-Server-Backup).InstallState
  $BackupServerIsOnline = Test-Connection -ComputerName $ComputerName -Count 2 -Quiet
  if ($BackupFeature -eq "Installed") {
      if ($BackupServerIsOnline) {
          $Date = Get-Date -Format "yyyy-MM-dd"
          $Target = "\\$ComputerName\$Share\$Prefix-$Date"
          $LogDirectory = "C:\BackupLogs"
        $LogFile = "$LogDirectory\$Prefix-$Date"
          if (Test-Path $Target) { Remove-Item -Path $Target -Recurse -Force }
          New-Item -ItemType Directory -Path $Target -Force | Out-Null
          if (Test-Path $LogDirectory) { New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null }
          $Expression = "wbadmin START BACKUP -systemState -vssFull -backupTarget:$Target -noVerify -quiet"
          Invoke-Expression $Expression | Out-File -FilePath $LogFile
      } else {
          Write-Output "[x] The computer specified is not online."
      }
  } else {
      Write-Output "[x] The Windows-Server-Backup feature is not installed. Use the command below to install it."
      Write-Output " Install-WindowsFeature -Name Windows-Server-Backup"
  }
}

function Uninstall-Sysmon {
  Invoke-Expression "C:\'Program Files'\Sysmon\Sysmon64.exe -u"
  Remove-Item -Path "C:\Program Files\Sysmon" -Recurse -Force
}
