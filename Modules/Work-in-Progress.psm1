function Get-EventForwarders {
    param(
      [Parameter(Mandatory)][string]$ComputerName,
      [Parameter(Mandatory)][string]$Subscription = "Forwarded Events"
    )
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        $Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\EventCollector\Subscriptions\$Subscription\EventSources"
        $EventForwarders = (Get-ChildItem $Key).Name | ForEach-Object { $_.Split("\")[9] }
        return $EventForwarders
    }
}
