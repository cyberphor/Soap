Add-Type -AssemblyName System.Windows.Forms

function Notify {
    $global:balloon = New-Object System.Windows.Forms.NotifyIcon

    [void](Register-ObjectEvent -InputObject $balloon -EventName MouseDoubleClick -SourceIdentifier IconClicked -Action {
        $global:balloon.Dispose()
        Unregister-Event -SourceIdentifier IconClicked
        Remove-Job -Name IconClicked
        Remove-Variable -Name balloon -Scope Global
    })

    $path = (Get-Process -Id $pid).Path
    $balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
    $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
    $balloon.BalloonTipTitle = 'Title'
    $balloon.BalloonTipText = 'Text'
    $balloon.Visible = $true
    $balloon.ShowBalloonTip(10000)
}

<#
While ($true) {
    $LogonFailure = Get-WinEvent -LogName Security |  Where-Object { $_.Id -eq '4625' }
    if $LogonFailure {
      Notify
    }
}
#>

# REFERENCES
# https://mcpmag.com/articles/2017/09/07/creating-a-balloon-tip-notification-using-powershell.aspx
