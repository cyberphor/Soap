function Get-IpAddressRange {
  <#
      .SYNOPSIS
      Given a network ID in CIDR notation, returns an array of IPv4 address strings.

      .DESCRIPTION
      Given a network ID in CIDR notation, returns an array of IPv4 address strings.

      .PARAMETER Network
      Specifies the network ID in CIDR notation.

      .INPUTS
      None. You cannot pipe objects to Get-IpAddressRange.

      .OUTPUTS
      System.Array. Get-IpAddressRange returns an array of IPv4 address strings.

      .EXAMPLE
      Get-IpAddressRange -Network 192.168.2.0/30
      192.168.2.1
      192.168.2.2

      .EXAMPLE
      Get-IpAddressRange -Network 192.168.2.0/30, 192.168.3.0/30
      192.168.2.1
      192.168.2.2
      192.168.3.1
      192.168.3.2

      .EXAMPLE
      Get-IpAddressRange -Network 192.168.2.1/32
      192.168.2.1

      .LINK
      https://github.com/cyberphor/soap

      .NOTES
      https://community.spiceworks.com/topic/649706-question-on-splitting-a-string-in-powershell
      https://devblogs.microsoft.com/scripting/use-powershell-to-easily-convert-decimal-to-binary-and-back/
      https://stackoverflow.com/questions/28460208/what-is-the-idiomatic-way-to-slice-an-array-relative-to-both-of-its-ends
      https://community.idera.com/database-tools/powershell/powertips/b/tips/posts/converting-binary-data-to-ip-address-and-vice-versa
  #>
  Param([Parameter(Mandatory)][string[]]$Network)
  $IpAddressRange = @()
  $Network |
  foreach {
      if ($_.Contains('/')) {
          $NetworkId = $_.Split('/')[0]
          $SubnetMask = $_.Split('/')[1]
          if ([ipaddress]$NetworkId -and ($SubnetMask -eq 32)) {
              $IpAddressRange += $NetworkId          
          } elseif ([ipaddress]$NetworkId -and ($SubnetMask -le 32)) {
              $Wildcard = 32 - $SubnetMask
              $NetworkIdBinary = ConvertTo-BinaryString $NetworkId
              $NetworkIdIpAddressBinary = $NetworkIdBinary.SubString(0,$SubnetMask) + ('0' * $Wildcard)
              $BroadcastIpAddressBinary = $NetworkIdBinary.SubString(0,$SubnetMask) + ('1' * $Wildcard)
              $NetworkIdIpAddress = ConvertTo-IpAddress $NetworkIdIpAddressBinary
              $BroadcastIpAddress = ConvertTo-IpAddress $BroadcastIpAddressBinary
              $NetworkIdInt32 = [convert]::ToInt32($NetworkIdIpAddressBinary,2)
              $BroadcastIdInt32 = [convert]::ToInt32($BroadcastIpAddressBinary,2)
              $NetworkIdInt32..$BroadcastIdInt32 | 
              foreach {
                  $BinaryString = [convert]::ToString($_,2)
                  $Address = ConvertTo-IpAddress $BinaryString
                  $IpAddressRange += $Address
              }            
          }
      }
  }
  return $IpAddressRange
}