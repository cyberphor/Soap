function Send-Alert {
  <#
      .SYNOPSIS
      Sends an alert. 

      .DESCRIPTION
      When called, this function will either write to the Windows Event log, send an email, or generate a Windows balloon tip notification.
      
      .LINK
      https://mcpmag.com/articles/2017/09/07/creating-a-balloon-tip-notification-using-powershell.aspx
  #>
  [CmdletBinding(DefaultParameterSetName = 'Log')]
  Param(
      [Parameter(Mandatory, Position = 0)][ValidateSet("Balloon","Log","Email")][string]$AlertMethod,
      [Parameter(Mandatory, Position = 1)]$Subject,
      [Parameter(Mandatory, Position = 2)]$Body,
      [Parameter(ParameterSetName = "Log")][string]$LogName,
      [Parameter(ParameterSetName = "Log")][string]$LogSource,
      [Parameter(ParameterSetName = "Log")][ValidateSet("Information","Warning")]$LogEntryType = "Warning",
      [Parameter(ParameterSetName = "Log")][int]$LogEventId = 1,
      [Parameter(ParameterSetName = "Email")][string]$EmailServer,
      [Parameter(ParameterSetName = "Email")][string]$EmailServerPort,
      [Parameter(ParameterSetName = "Email")][string]$EmailAddressSource,
      [Parameter(ParameterSetName = "Email")][string]$EmailPassword,
      [Parameter(ParameterSetName = "Email")][string]$EmailAddressDestination
  )
  if ($AlertMethod -eq "Balloon") {
      Add-Type -AssemblyName System.Windows.Forms
      Unregister-Event -SourceIdentifier IconClicked -ErrorAction Ignore
      Remove-Job -Name IconClicked -ErrorAction Ignore
      Remove-Variable -Name Balloon -ErrorAction Ignore
      $Balloon = New-Object System.Windows.Forms.NotifyIcon
      [void](Register-ObjectEvent `
          -InputObject $Balloon `
          -EventName MouseDoubleClick `
          -SourceIdentifier IconClicked `
          -Action { $Balloon.Dispose() }
      )
      $IconPath = (Get-Process -Id $pid).Path
      $Balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($IconPath)
      $Balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
      $Balloon.BalloonTipTitle = $Subject
      $Balloon.BalloonTipText = $Body
      $Balloon.Visible = $true
      $Balloon.ShowBalloonTip(10000)
  } elseif ($AlertMethod -eq "Log") {
      $LogExists = Get-EventLog -LogName $LogName -Source $LogSource -ErrorAction Ignore -Newest 1
      if (-not $LogExists) {
          New-EventLog -LogName $LogName -Source $LogSource -ErrorAction Ignore
      }
      Write-EventLog `
          -LogName $LogName `
          -Source $LogSource `
          -EntryType $LogEntryType `
          -EventId $LogEventId `
          -Message $Body
  } elseif ($AlertMethod -eq "Email") {
      $EmailClient = New-Object Net.Mail.SmtpClient($EmailServer, $EmailServerPort)
      $EmailClient.EnableSsl = $true
      $EmailClient.Credentials = New-Object System.Net.NetworkCredential($EmailAddressSource, $EmailPassword)
      $EmailClient.Send($EmailAddressSource, $EmailAddressDestination, $Subject, $Body)
  }
}