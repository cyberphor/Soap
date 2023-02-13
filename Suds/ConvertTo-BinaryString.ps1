function ConvertTo-BinaryString {
  <#
      .SYNOPSIS
      Converts the provided IP address into binary.

      .DESCRIPTION
      Outputs a string of binary digits if the provided input is a valid IP address.

      .INPUTS
      This function accepts piped objects.

      .OUTPUTS
      System.String.

      .EXAMPLE
      PS> "8.8.8.8" | ConvertTo-BinaryString
      1000000010000000100000001000

      .LINK
      https://github.com/cyberphor/Soap
  #>
  Param([parameter(Mandatory,ValueFromPipeline)][IPAddress]$IpAddress)
  $Integer = $IpAddress.Address
  $ReverseIpAddress = [IPAddress][String]$Integer
  $BinaryString = [Convert]::toString($ReverseIpAddress.Address,2)
  return $BinaryString
}