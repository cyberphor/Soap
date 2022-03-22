Import-Module ActiveDirectory

$30_Days_Ago = (Get-Date).AddDays(-30)
$Filter = { LastLogonDate -le $30_Days_Ago }
$SearchBase = Read-Host -Prompt 'Distinguished Name (OU Path in LDAP Format)'

Get-ADComputer -Filter $Filter -Properties LastLogonDate | 
foreach {
    if ($_.Enabled) {
        Set-ADComputer $_.SamAccountName -Description $('Last Login - ' + $_.LastLogonDate)
        Disable-ADAccount $_.SamAccountName
    }
} 

# EXAMPLE OU PATH: OU=Computers,OU=HQ,OU=EvilCorp,DC=vanilla,DC=sky,DC=net
