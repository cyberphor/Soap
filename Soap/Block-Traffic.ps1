function Block-Traffic {
  <#
      .SYNOPSIS
      Blocks network traffic destined to the provided IP address and/or port. 

      .DESCRIPTION
      Adds a rule to the local Windows Firewall policy so network traffic destined to the provided IP address and/or port is blocked.

      .PARAMETER Protocol
      Specifies the protocol to block.

      .PARAMETER IpAddress
      Specifies the IP address to block traffic.

      .PARAMETER Port
      Specifies the port to block traffic.

      .INPUTS
      None. You cannot pipe objects to this function.

      .OUTPUTS
      None. 

      .EXAMPLE
      PS> Block-Traffic -Protocol UDP -IpAddress 8.8.8.8 -Port 53

      .LINK
      https://github.com/cyberphor/Soap
  #>
  Param(
      [ValidateSet("Any","TCP","UDP","ICMPv4","ICMPv6")][string]$Protocol = "Any",
      [Parameter(Mandatory)][ipaddress]$IpAddress,
      $Port = "Any"
  )
  New-NetFirewallRule `
      -DisplayName "Block '$Protocol' traffic to '$Port' port on $IpAddress" `
      -Direction Outbound `
      -Protocol $Protocol `
      -RemoteAddress $IpAddress `
      -RemotePort $RemotePort `
      -Action Block
} 