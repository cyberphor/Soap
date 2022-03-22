Param(
    [switch]$Remove,
    [switch]$CreateDomainAdmin
)

$Domain = 'vanilla.sky.net' # change me
$DC1 = 'T800' # change me
$FirstName = 'Elliot' # change me
$LastName = 'Alderson' # change me
$FullName = $LastName + ', ' + $FirstName
$SamAccountName = $FirstName.ToLower() + '.' + $LastName.ToLower()
$UserPrincipalName = $SamAccountName + '@' + $Domain
$Password = ConvertTo-SecureString 'AdministratorPassword2020!' -AsPlainText -Force # change me
$Description = 'Your Security Administrator' # change me
$Group = 'Domain Admins' # change me

function Check-Credentials {
    $UserId = [Security.Principal.WindowsIdentity]::GetCurrent()
    $AdminId = [Security.Principal.WindowsBuiltInRole]::Administrator
    $CurrentUser = New-Object Security.Principal.WindowsPrincipal($UserId)
    $RunningAsAdmin = $CurrentUser.IsInRole($AdminId)
    if (-not $RunningAsAdmin) { 
        Write-Output '[x] This script requires administrator privileges.'
        break
    }
}

function Install-RequiredFeatures() {
    if ((Get-WindowsFeature AD-Domain-Services).InstallState -ne 'Installed') {
        Write-Host "[!] Installing the 'Active Directory Domain Services' feature."
        $ExitCode = (Install-WindowsFeature AD-Domain-Services -IncludeManagementTools).ExitCode
        Write-Host " ---> $ExitCode"
    } else { Write-Host "[+] The 'Active Directory Domain Services' feature is already installed." }

    if ((Get-WindowsFeature DNS).InstallState -ne 'Installed') {
        Write-Host "[!] Installing the 'Domain Name System (DNS)' feature."
        $ExitCode = (Install-WindowsFeature DNS -IncludeManagementTools).ExitCode
        Write-Host " ---> $ExitCode"
    } else { Write-Host "[+] The 'Domain Name System (DNS)' feature is already installed." }
}

function Create-ActiveDirectoryForest() {
    if ($env:COMPUTERNAME -ne $DC1) { Rename-Computer -NewName $DC1 -Force }
    if ((Get-Service adws).Status -ne 'Running') {
        Write-Host "[!] Deploying the '$Domain' domain."
        Install-ADDSForest -DomainName $Domain -InstallDns -SafeModeAdministratorPassword $Password -Force
        break
    }
}

function Create-DomainAdmin() {
    if ((Get-Service adws).Status -eq 'Running') {
        $UserExists = [bool] (Get-ADUser -Filter { SamAccountName -eq $SamAccountName }) 
        if ($UserExists -ne $true) {
            Write-Host "[!] Creating a Domain Admin:"
            New-ADUser `
                -GivenName $FirstName `
                -Surname $LastName `
                -Name $FullName `
                -SamAccountName $SamAccountName `
                -UserPrincipalName $UserPrincipalName `
                -AccountPassword $Password `
                -ChangePasswordAtLogon $true `
                -Description $Description 
            Enable-ADAccount -Identity $SamAccountName
            Add-ADGroupMember -Identity $Group -Members $SamAccountName
            $DomainAdmin = (Get-ADUser $SamAccountName).UserPrincipalName
            Write-Host " ---> $DomainAdmin"
        } else { Write-Host "[+] The user '$UserPrincipalName' already exists." }
    }
}

function Remove-ActiveDirectoryForest {
    $SomethingChanged = $false
    if ([bool] (Get-ADUser -Filter { SamAccountName -eq $SamAccountName })) { 
        Remove-ADUser $SamAccountName 
        $SomethingChanged = $true
    }
    if ((Get-WindowsFeature AD-Domain-Services).InstallState -eq 'Installed') {
        (Remove-WindowsFeature AD-Domain-Services).ExitCode
        $SomethingChanged = $true
    } 
    if ((Get-WindowsFeature DNS).InstallState -eq 'Installed') {
        (Remove-WindowsFeature DNS).ExitCode
        $SomethingChanged = $true
    } 
    if ($SomethingChanged) { Restart-Computer }
}

Check-Credentials
if ($Remove) { Remove-ActiveDirectoryForest }
elseif ($CreateDomainAdmin) { Create-DomainAdmin }
else {
    Install-RequiredFeatures
    Create-ActiveDirectoryForest
    Create-DomainAdmin
}
