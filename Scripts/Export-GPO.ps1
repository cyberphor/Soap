Clear-Host
Write-Output "`n[+] Available GPOs:"
$AllGPOs = (Get-GPO -All).DisplayName
$AllGPOs | ForEach-Object { Write-Output " -   $_"}
$GPOName = Read-Host -Prompt "`n[+] Which GPO do you want exported? `n -   GPO Name"

if ($AllGPOs -contains $GPOName) {
    $GPOBackupFolder = "$PWD\" + ($GPOName).Replace(" ", "-") + "GPO"
    $FindingGPOBackupFolder = Test-Path -Path $GPOBackupFolder
    if (-not $FindingGPOBackupFolder) {
        New-Item -Type Directory -Path $GPOBackupFolder | Out-Null
    }
    $GPOGuid = '{' + (Backup-GPO -Name $GPOName -Path $GPOBackupFolder).Id + '}'

    $OldDC = $env:COMPUTERNAME
    $OldNetBIOSName = $env:USERDOMAIN
    $OldDNSDomainName = $env:USERDNSDOMAIN

    $NewDC = 'DC1'
    $NewNetBIOSName = 'CONTOSO'
    $NewDNSDomainName = 'contoso.com'

    $Files = @(
        "$GPOBackupFolder\$GPOGuid\Backup.xml"
        "$GPOBackupFolder\$GPOGuid\bkupInfo.xml" 
        "$GPOBackupFolder\$GPOGuid\gpreport.xml"
    ) 

    $Files |
    ForEach-Object {
        Write-Output "`n[+] Scrubbing $_"
        (Get-Content -Path $_) `
        -replace $OldDC, $NewDC `
        -replace $OldDNSDomainName, $NewDNSDomainName `
        -replace $OldNetBIOSName, $NewNetBIOSName |
        Set-Content $_
        Write-Output " -   Done."
    }
}
