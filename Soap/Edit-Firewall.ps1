function Enable-Firewall {
  <#
      .SYNOPSIS
      Enables the firewall. 

      .DESCRIPTION
      Enables the domain, public, and private firewall profile. 

      .INPUTS
      None. This function does not accept piped objects.

      .OUTPUTS
      None.

      .EXAMPLE
      PS> Enable-Firewall

      .LINK
      https://github.com/cyberphor/Soap
  #>
  Set-NetFirewallProfile -Name domain,public,private -Enabled true
}