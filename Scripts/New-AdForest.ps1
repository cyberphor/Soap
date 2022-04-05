Param(
    [String]$DomainName = 'evil.corp',
    [String]$DomainController = 'dc1',
    [SecureString]$DirectoryServicesRestoreModePassword = $(ConvertTo-SecureString -AsPlainText -Force "1qaz2wsx!QAZ@WSX"),
    [String]$DomainAdminFirstName = 'Elliot',
    [String]$DomainAdminLastName = 'Alderson',
    [String]$DomainAdminFullName = $DomainAdminLastName + ', ' + $DomainAdminFirstName,
    [String]$DomainAdminAccountName = $DomainAdminFirstName.ToLower() + '.' + $DomainAdminLastName.ToLower(),
    [String]$DomainAdminUserPrincipalName = $DomainAdminSamAccountName + '@' + $DomainName,
    [SecureString]$DomainAdminPassword = $(ConvertTo-SecureString -AsPlainText -Force "1qaz2wsx!QAZ@WSX"),
    [String]$DomainAdminDescription = 'Domain Administrator',
    [String]$DomainAdminGroup = 'Domain Admins'
)

function Install-RequiredFeatures {
    $AdDomainServices = (Get-WindowsFeature AD-Domain-Services).InstallState
    $Dns = (Get-WindowsFeature DNS).InstallState

    if ($AdDomainServices -ne 'Installed') {
        (Install-WindowsFeature AD-Domain-Services -IncludeManagementTools).ExitCode
    } 

    if ($Dns -ne 'Installed') {
        (Install-WindowsFeature DNS -IncludeManagementTools).ExitCode
    }
}

function Rename-DomainController {
    if ($env:COMPUTERNAME -ne $DomainController) { 
        Rename-Computer -NewName $DomainController -Force
    }
}

function Install-AdForest {
    $ActiveDirectoryWebServices = (Get-Service -Name ADWS).Status
    if ($ActiveDirectoryWebServices -ne 'Running') {
        Install-ADDSForest -DomainName $DomainName -InstallDns -SafeModeAdministratorPassword $DirectoryServicesRestoreModePassword -NoRebootOnCompletion -Force
    }
}

function New-AdDomainAdmin {
    $AdDomainServices = (Get-WindowsFeature AD-Domain-Services).InstallState
    if ($AdDomainServices -eq 'Running') {
        $UserExists = [bool](Get-ADUser -Filter {SamAccountName -eq $DomainAdminSamAccountName}) 
        if ($UserExists -ne $true) {
            New-ADUser `
                -GivenName $DomainAdminFirstName `
                -Surname $DomainAdminLastName `
                -Name $DomainAdminFullName `
                -SamAccountName $DomainAdminSamAccountName `
                -UserPrincipalName $DomainAdminUserPrincipalName `
                -AccountPassword $DomainAdminPassword `
                -ChangePasswordAtLogon $true `
                -Description $DomainAdminDescription 
            Enable-ADAccount -Identity $DomainAdminSamAccountName
            Add-ADGroupMember -Identity $DomainAdminGroup -Members $DomainAdminSamAccountName
        }
    }

    $TaskName = "Create the first Domain Admin account"
    $TaskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-File C:\Scripts\New-AdForest.ps1'
    $TaskTrigger = New-ScheduledTaskTrigger -AtLogOn
    $TaskDescription = "Creates the first Domain Admin account for this Active Directory forest."
    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $TaskAction `
        -Trigger $TaskTrigger `
        -Description $TaskDescription
}

Install-RequiredFeatures
Install-AdForest
Rename-DomainController
New-AdDomainAdmin