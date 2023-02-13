function Set-AuditPolicy {
  <#
      .SYNOPSIS
      Configures the local audit policy. 

      .DESCRIPTION
      Configures the local audit policy using recommendations from Microsoft, DISA, or Malware Archaeology.

      .INPUTS
      None.

      .OUTPUTS
      None.

      .EXAMPLE
      Set-AuditPolicy.ps1 -Source "Malware Archaeology"

      .LINK
      https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations 
      https://www.malwarearchaeology.com/s/Windows-Logging-Cheat-Sheet_ver_Feb_2019.pdf
      https://cryptome.org/2014/01/nsa-windows-event.pdf
      https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/ 
  #>
  Param(
      [ValidateSet('Microsoft','DISA','Malware Archaeology')]$Source,
      [switch]$EnableDnsLogging,
      [switch]$DisableDnsLogging
  )

  function Set-AuditPolicyUsingMicrosoftRecommendations {
      auditpol /clear /y

      # Account Logon
      # - Event IDs: 4774, 4776
      auditpol /set /subcategory:"Credential Validation" /success:enable

      # Account Management
      # - Event IDs: 4741, 4742, 4743
      auditpol /set /subcategory:"Computer Account Management" /success:enable

      # - Event IDs: 4739, 4782, 4793
      auditpol /set /subcategory:"Other Account Management Events" /success:enable

      # - Event IDs: 4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737, 4754, 4755, 4756, 4757, 4758, 4764, 4799
      auditpol /set /subcategory:"Security Group Management" /success:enable

      # - Event IDs: 4738, 4740, 4765, 4767, 4780, 4781, 
      auditpol /set /subcategory:"User Account Management" /success:enable

      # Detailed Tracking
      # - Event ID: 4688
      auditpol /set /subcategory:"Process Creation" /success:enable

      # Logon/Logoff
      # - Event IDs: 4624, 4625
      auditpol /set /subcategory:"Logon" /success:enable /failure:enable

      # - Event IDs: 4634, 4647
      auditpol /set /subcategory:"Logoff" /success:enable

      # - Event IDs: 4672, 4964
      auditpol /set /subcategory:"Special Logon" /success:enable

      # Policy Change
      # - Event IDs: 4715, 4719, 4817, 4902, 4904, 4905, 4906, 4907, 4908, 4912
      auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable

      # - Event IDs: 4706, 4707, 4713, 4716, 4717, 4718, 4865, 4866, 4867
      auditpol /set /subcategory:"Authentication Policy Change" /success:enable

      # System
      # - Event IDs: 5478, 5479, 5480, 5483, 5484, 5485
      auditpol /set /subcategory:"IPSec Driver" /success:enable /failure:enable

      # - Event IDs: 4608, 4609, 4616, 4621
      auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable

      # - Event IDs: 4610, 4611, 4614, 4622, 4697
      auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable

      # - Event IDs: 4612, 4615, 4618, 5038, 5056, 5061, 5890, 6281, 6410
      auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
  }

  function Set-AuditPolicyUsingMalwareArchaeologyRecommendations {
      # DNS 
      wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:true

      # DHCP
      wevtutil sl "Microsoft-Windows-Dhcp-Client/Operational" /e:true

      auditpol /clear /y

      # Account Logon
      auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

      auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable

      # Account Management
      auditpol /set /category:"Account Management" /success:enable /failure:enable

      # Detailed Tracking
      auditpol /set /subcategory:"Plug and Play Events" /success:enable

      auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

      auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable

      auditpol /set /subcategory:"Token Right Adjusted Events" /success:enable

      # Logon/Logoff
      auditpol /set /subcategory:"Account Lockout" /success:enable

      auditpol /set /subcategory:"Group Membership" /success:enable

      auditpol /set /subcategory:"Logon" /success:enable

      auditpol /set /subcategory:"Logoff" /success:enable

      auditpol /set /subcategory:"Network Policy Server" /success:enable

      auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable

      auditpol /set /subcategory:"Special Logon" /success:enable

      # Object Access
      auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable

      auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable

      auditpol /set /subcategory:"Detailed File Share" /success:enable

      auditpol /set /subcategory:"File Share" /success:enable /failure:enable

      auditpol /set /subcategory:"File System" /success:enable

      auditpol /set /subcategory:"Filtering Platform Connection" /success:enable

      auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable

      auditpol /set /subcategory:"Registry" /success:enable

      auditpol /set /subcategory:"SAM" /success:enable

      # Policy Change
      auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable

      auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable

      auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable

      auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable 

      # Privilege Use
      auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

      # System
      auditpol /set /subcategory:"IPsec Driver" /success:enable

      auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable

      auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable

      auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable

      # Process Command Line
      reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
  }

  function Set-AuditPolicyUsingTheDisaStigForWindows10 {
      auditpol /clear /y

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

      # V-220782: the Application event log must be restricted to the following accounts/groups: Eventlog, SYSTEM, Administrators


      # V-220783: the Security event log must be restricted to the following accounts/groups: Eventlog, SYSTEM, Administrators


      # V-220784: the System event log must be restricted to the following accounts/groups: Eventlog, SYSTEM, Administrators


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
      reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

      # V-220860: PowerShell script block logging must be enabled on Windows 10.
      reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

      # V-220913: Audit policy using subcategories must be enabled
      reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f

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
      Remove-Item $FileName

      # V-250318: PowerShell Transcription must be enabled on Windows 10.
      reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f
  }

  if ($Source) {
      $SourcePrompt = Read-Host -Prompt "This script will implement the baseline Windows 10 audit policy recommended by $Source.`nDo you want to continue? (y/n)"
      if ($SourcePrompt.ToLower() -eq "y") {
          switch ($Source) {
              "Microsoft" { Set-AuditPolicyUsingMicrosoftRecommendations }
              "Malware Archaeology" { Set-AuditPolicyUsingMalwareArchaeologyRecommendations }
              "DISA" { Set-AuditPolicyUsingTheDisaStigForWindows10 }
          }
      }
  }

  if ($EnableDnsLogging) {
      $EnableDnsLoggingPrompt = Read-Host -Prompt "This script will configure the local DNS client to log all DNS queries. `nDo you want to continue? (y/n)"
      if ($EnableDnsLoggingPrompt.ToLower() -eq "y") {
          wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true   
      }
  } elseif ($DisableDnsLogging) {
      $DisableDnsLoggingPrompt = Read-Host -Prompt "This script will configure the local DNS client to NOT log all DNS queries. `nDo you want to continue? (y/n)"
      if ($DisableDnsLoggingPrompt.ToLower() -eq "y") {
          wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:false  
      }
  }
}