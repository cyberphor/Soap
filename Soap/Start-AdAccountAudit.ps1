function Start-AdAccountAudit {
  <#
       .SYNOPSIS
       Disables inactive domain accounts. 
       
       .DESCRIPTION
       Disables domain accounts that have been inactive for 45 days and moves them into a container called "Disabled." This function will create a Active Directory container called "Disabled" if it does not exist.  

       .INPUTS
       None. You cannot pipe objects to this function.

       .OUTPUTS
       None. 

       .EXAMPLE
       PS> Start-AdAccountAudit

       .LINK
       https://github.com/cyberphor/Soap
   #>
   $Domain = (Get-ADDomain).DistinguishedName
   $DisabledContainer = "OU=Disabled,$Domain"
   $DisabledContainerDoesNotExist = [bool](Get-ADOrganizationalUnit -Identity $DisabledContainer) -eq $false
   if ($DisabledContainerDoesNotExist) {
       New-ADOrganizationalUnit -Name "Disabled" -Path $Domain
   }

   # search for accounts w/lastlogondate beyond 45 days, disable them, and then move them to a "Disabled" container
   Get-ADUser -Filter { LastLogonDate -le (Get-Date).AddDays(-45) } | 
   ForEach-Object {
       Disable-ADAccount $_.SamAccountName
       Move-ADObject -Identity $_.DistinguishedName -TargetPath $DisabledContainer
   } 
}