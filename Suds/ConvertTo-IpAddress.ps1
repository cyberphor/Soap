function ConvertTo-IpAddress {
  <#
      .SYNOPSIS
      Converts the provided string into an IP address.

      .DESCRIPTION
      Outputs an IP address if the provided input is a string of binary digits. 

      .INPUTS
      This function accepts piped objects.

      .OUTPUTS
      System.String.

      .EXAMPLE
      PS> ConvertTo-IpAddress -BinaryString 1000000010000000100000001000
      8.8.8.8

      .LINK
      https://github.com/cyberphor/Soap
  #>
  Param([parameter(Mandatory,ValueFromPipeline)][string]$BinaryString)
  $Integer = [System.Convert]::ToInt64($BinaryString,2).ToString()
  $IpAddress = ([System.Net.IPAddress]$Integer).IpAddressToString
  return $IpAddress
}