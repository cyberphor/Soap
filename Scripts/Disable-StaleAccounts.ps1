Import-Module ActiveDirectory

$SearchBase = Read-Host -Prompt 'Distinguished Name (OU Path in LDAP Format) to Scrub'
# $SearchBase = 'OU=Users,OU=HQ,OU=EvilCorp,DC=sky,DC=net'
$30_Days_Ago = (Get-Date).AddDays(-30)
$Filter = { LastLogonDate -le $30_Days_Ago }

$DomainRoot = $(Get-ADDomain).DistinguishedName
$DisabledUsersOu = "OU=Disabled Users," + $DomainRoot
$DisabledUsersOuExists = (Get-ADOrganizationalUnit -Filter *).DistinguishedName -eq $DisabledUsersOu
if (-not ($DisabledUsersOuExists)) {
    New-ADOrganizationalUnit -Name "Disabled Users" -Path $DomainRoot
}

$VipUsers = (Get-ADGroup -Identity 'VIP Users').Sid

Get-ADUser -Filter $Filter -SearchBase $SearchBase -Properties LastLogonDate,Description | 
Where-Object { $VipUsers -notcontains $_.Sid } |
foreach {
    if ($_.Enabled) {
        Set-ADUser $_.SamAccountName -Description $('Last Login - ' + $_.LastLogonDate)
        Disable-ADAccount $_.SamAccountName
    }

    Move-ADObject -Identity $_.DistinguishedName -TargetPath $DisabledUsersOu
} 
