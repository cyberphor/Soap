function Disable-Firewall {
  <#
      .SYNOPSIS
      Disables the firewall. 

      .DESCRIPTION
      Disables the domain, public, and private firewall profile. 

      .INPUTS
      None. This function does not accept piped objects.

      .OUTPUTS
      None.

      .EXAMPLE
      PS> Disable-Firewall

      .LINK
      https://github.com/cyberphor/Soap
  #>
  Set-NetFirewallProfile -Name domain,public,private -Enabled False
} 