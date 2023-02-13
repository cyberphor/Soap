function Enable-IPv6 {
  <#
      .SYNOPSIS
      Enables IPv6. 

      .DESCRIPTION
      Enables IPv6 binding for on network adapters. 

      .INPUTS
      None. This function does not accept piped objects.

      .OUTPUTS
      None.

      .EXAMPLE
      PS> Disable-Firewall

      .LINK
      https://github.com/cyberphor/Soap
  #>
  Enable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
}