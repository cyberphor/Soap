function Import-AdUsersFromCsv {
    $Password = ConvertTo-SecureString -String '1qaz2wsx!QAZ@WSX' -AsPlainText -Force
    Import-Csv -Path .\users.csv |
    ForEach-Object {
        $Name = $_.LastName + ', ' + $_.FirstName
        $SamAccountName = ($_.FirstName + '.' + $_.LastName).ToLower()
        $UserPrincipalName = $SamAccountName + '@evilcorp.local'
        $Description = $_.Description
        $ExpirationDate = Get-Date -Date 'October 31 2022'
        New-AdUser `
            -Name $Name `
            -DisplayName $Name `
            -GivenName $_.FirstName `
            -Surname $_.LastName `
            -SamAccountName $SamAccountName `
            -UserPrincipalName $UserPrincipalName `
            -Description $Description `
            -ChangePasswordAtLogon $true `
            -AccountExpirationDate $ExpirationDate `
            -Enabled $true `
            -Path 'OU=Users,OU=evilcorp,DC=local' `
            -AccountPassword $Password
    }
}

function Start-AdBackup {
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [string]$Share = "Backups",
        [string]$Prefix = "AdBackup"
    )
    $BackupFeature = (Install-WindowsFeature -Name Windows-Server-Backup).InstallState
    $BackupServerIsOnline = Test-Connection -ComputerName $ComputerName -Count 2 -Quiet
    if ($BackupFeature -eq "Installed") {
        if ($BackupServerIsOnline) {
            $Date = Get-Date -Format "yyyy-MM-dd"
            $Target = "\\$ComputerName\$Share\$Prefix-$Date"
            $LogDirectory = "C:\BackupLogs"
    	    $LogFile = "$LogDirectory\$Prefix-$Date"
            if (Test-Path $Target) { Remove-Item -Path $Target -Recurse -Force }
            New-Item -ItemType Directory -Path $Target -Force | Out-Null
            if (Test-Path $LogDirectory) { New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null }
            $Expression = "wbadmin START BACKUP -systemState -vssFull -backupTarget:$Target -noVerify -quiet"
            Invoke-Expression $Expression | Out-File -FilePath $LogFile
        } else {
            Write-Output "[x] The computer specified is not online."
        }
    } else {
        Write-Output "[x] The Windows-Server-Backup feature is not installed. Use the command below to install it."
        Write-Output " Install-WindowsFeature -Name Windows-Server-Backup"
    }
}