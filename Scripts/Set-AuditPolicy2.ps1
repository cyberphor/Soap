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
auditpol /set /subcategory:"PNP Activity" /success:enable

# V-220754
auditpol /set /subcategory:"Process Creation" /success:enable

# V-220755
auditpol /set /subcategory:"Account Lockout" /failure:enable

# V-220756
auditpol /set /subcategory:"Group Membership" /success:enable

# V-220757
auditpol /set /subcategory:"Logoff" /success:enable

# V-220758
auditpol /set /subcategory:"Logon" /success:failure

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

# V-250318: PowerShell Transcription must be enabled on Windows 10.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f