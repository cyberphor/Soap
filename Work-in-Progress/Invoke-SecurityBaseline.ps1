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