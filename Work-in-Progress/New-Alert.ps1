function New-Alert {
  Param([Parameter(Mandatory, ValueFromPipeline)][string]$Message)
  New-EventLog -LogName "Alerts" -Source "Custom" -ErrorAction SilentlyContinue
  Write-EventLog `
      -Category 0 `
      -EntryType Warning `
      -EventID 5000 `
      -LogName "Alerts" `
      -Message $Message `
      -Source "Custom" 
}