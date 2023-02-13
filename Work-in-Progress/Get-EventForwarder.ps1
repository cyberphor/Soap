function Get-EventForwarder {
  param(
    [string]$ComputerName,
    [string]$Subscription = "Forwarded Events"
  )
  Invoke-Command -ComputerName $ComputerName -ArgumentList $Subscription -ScriptBlock {
      $Subscription = $args[0]
      $Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\EventCollector\Subscriptions\$Subscription\EventSources"
      $EventForwarders = (Get-ChildItem $Key).Name | ForEach-Object { $_.Split("\")[9] }
      return $EventForwarders
  }
}