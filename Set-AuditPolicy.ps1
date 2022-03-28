$Prompt = Read-Host -Prompt "This script will implement the baseline Windows 10 audit policy recommended by Microsoft.`nDo you want to continue? (y/n)"
if ($Prompt.ToLower() -eq "y") {
    # clear the current audit policy
    auditpol /clear /y

    # Account Logon
    # - Event IDs: 4774, 4776
    auditpol /set /subcategory:”Credential Validation” /success:enable

    # Account Management
    # - Event IDs: 4741, 4742, 4743
    auditpol /set /subcategory:”Computer Account Management” /success:enable

    # - Event IDs: 4739, 4782, 4793
    auditpol /set /subcategory:“Other Account Management Events” /success:enable

    # - Event IDs: 4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737, 4754, 4755, 4756, 4757, 4758, 4764, 4799
    auditpol /set /subcategory:“Security Group Management” /success:enable

    # - Event IDs: 4738, 4740, 4765, 4767, 4780, 4781, 
    auditpol /set /subcategory:“User Account Management” /success:enable

    # Detailed Tracking
    # - Event ID: 4688
    auditpol /set /subcategory:“Process Creation” /success:enable

    # Logon and Logoff
    # - Event IDs: 4624, 4625
    auditpol /set /subcategory:“Logon” /success:enable /failure:enable

    # - Event IDs: 4634, 4647
    auditpol /set /subcategory:“Logoff” /success:enable

    # - Event IDs: 4672, 4964
    auditpol /set /subcategory:“Special Logon” /success:enable

    # Policy Change
    # - Event IDs: 4715, 4719, 4817, 4902, 4904, 4905, 4906, 4907, 4908, 4912
    auditpol /set /subcategory:“Audit Policy Change” /success:enable /failure:enable

    # - Event IDs: 4706, 4707, 4713, 4716, 4717, 4718, 4865, 4866, 4867
    auditpol /set /subcategory:“Authentication Policy Change” /success:enable

    # System
    # - Event IDs: 5478, 5479, 5480, 5483, 5484, 5485
    auditpol /set /subcategory:“IPSec Driver” /success:enable /failure:enable

    # - Event IDs: 4608, 4609, 4616, 4621
    auditpol /set /subcategory:“Security State Change” /success:enable /failure:enable

    # - Event IDs: 4610, 4611, 4614, 4622, 4697
    auditpol /set /subcategory:“Security System Extension” /success:enable /failure:enable

    # - Event IDs: 4612, 4615, 4618, 5038, 5056, 5061, 5890, 6281, 6410
    auditpol /set /subcategory:“System Integrity” /success:enable /failure:enable
}
