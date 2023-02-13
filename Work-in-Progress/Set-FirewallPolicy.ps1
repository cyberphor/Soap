function Set-FirewallPolicy {
  Param(
      [string[]]$AuthorizedProtocol = "ICMP",
      [int[]]$AuthorizedPorts = @(53,80,443,5985),
      [int[]]$RemoteManagementPorts = @(5985),
      [ipaddress]$ManagementIpAddress
  )

  Write-Output "Configuring DoD Windows 10 STIG Requirement V-220725 (Inbound exceptions to the firewall on Windows 10 domain workstations must only allow authorized remote management hosts)."
  
  # enable Windows Remote Management
  Enable-PSRemoting -Force
  if ($ManagementIpAddress) {
      Set-Item -Path WSMan:\localhost\Service\ -Name IPv4Filter -Value $ManagementIpAddress
  }

  # disable all rules allowing inbound connections (except for Windows Remote Management)
  Get-NetFirewallRule -Direction Inbound -Action Allow |
  ForEach-Object { 
      $NotAuthorizedPort = $RemoteManagementPorts -notcontains $($_ | Get-NetFirewallPortFilter).RemotePort
      if ($NotAuthorizedPort) {
          $_ | Set-NetFirewallRule -Enabled False
      }
  }

  # disable all rules allowing outbound connections except for those authorized
  Get-NetFirewallRule -Direction Outbound -Action Allow | 
  ForEach-Object { 
      $NotAuthorizedProtocol = $AuthorizedProtocols -notcontains $($_ | Get-NetFirewallPortFilter).Protocol
      $NotAuthorizedPort = $AuthorizedPorts -notcontains $($_ | Get-NetFirewallPortFilter).RemotePort
      if ($NotAuthorizedProtocol -or $NotAuthorizedPort) {
          $_ | Set-NetFirewallRule -Enabled False
      }
  }
}