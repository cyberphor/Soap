Import-Module ActiveDirectory

$30DaysAgo = (Get-Date).AddDays(-30)
$AtctsReport = Import-Csv $Report | Select Name, @{Name='TrainingDate';Expression={$_.'Date Awareness Training Completed'}}
$AdSearchBase = ''
$DisabledUsersOu = '' + $AdSearchBase
$AdUserAccounts = Get-AdUser -Filter * -SearchBase $AdSearchBase -Properties LastLogonDate
$VipUsers = $(Get-AdGroup -Identity 'VIP Users').Sid
$UsersInAtctsReport = $AtctsReport.Name.ToUpper() |
foreach {
    $SpaceBetweenFirstAndMiddle = $_.Substring($_.Length -2).Substring(0,1)
    if ($SpaceBetweenFirstAndMiddle) { $_ -replace ".$" }
}

$AdUserAccounts |
Where-Object { $VipUsers -notcontains $_.Sid } |
foreach {
    $NotCompliant = $false
    $Reason = 'Disabled:'

    if ($_.Surname -and $_.GivenName) {
        $FullName = ($_.Surname + ', ' + $_.GivenName).ToUpper()
    } else {
        $FullName = ($_.SamAccountName).ToUpper()
    }

    $AtctsProfile = $UsersInAtctsReport | Where-Object { $_ -like "$FullName*" }

    if (-not $AtctsProfile) {
        $NotCompliant = $true
        $Reason = $Reason + ' ATCTS profile does not exist.'
    }

    if ($AtctsProfile) {
        $TrainingDate = ($AtctsReport | Where-Object { $_.Name -like "$FullName*" }).TrainingDate
        $NewDate = $TrainingDate.Split('-')[0]+ $TrainingDate.Split('-')[2] + $TrainingDate.Split('-')[1]
        $ExpirationDate = (Get-Date $NewDate).AddYears(1).ToString('yyyy-MM-dd')
        if ($ExpirationDate -lt $(Get-Date -Format 'yyyy-MM-dd')){
            $NotCompliant = $true
            $Reason = $Reason + ' Training has expired.'
        }
    }

    if ($_.LastLogonDate -le $30DaysAgo) {
        $NotCompliant = $true
        $Reason = $Reason + 'Inactive for 30 days.'
    }

    if ($NotCompliant) {
        Set-AdUser $_.SamAccountName -Description $Reason
        Disable-AdAccount $_.SamAccountName
        Move-AdObject -Identity $_.DistinguishedName -TargetPath $DisabledUsersOu
        Write-Output "[+] $($_.Name) - $Reason"
    }
}
