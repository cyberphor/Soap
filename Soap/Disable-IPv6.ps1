function Disable-IPv6 {
  <#
      .SYNOPSIS
      Disables IPv6. 

      .DESCRIPTION
      Disables IPv6 binding on all network adapters. 

      .INPUTS
      None. This function does not accept piped objects.

      .OUTPUTS
      None.

      .EXAMPLE
      PS> Disable-Firewall

      .LINK
      https://github.com/cyberphor/Soap
  #>
  Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
}