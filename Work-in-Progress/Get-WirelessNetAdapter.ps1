function Get-WirelessNetAdapter {
  <#
      .EXAMPLE
      Get-WirelessNetAdapter
      ServiceName      : RtlWlanu
      MACAddress       : 00:13:EF:F3:6F:F5
      AdapterType      : Ethernet 802.3
      DeviceID         : 16
      Name             : Realtek 8812BU Wireless LAN 802.11ac USB NIC
      NetworkAddresses : 
      Speed            : 144400000

      ServiceName      : vwifimp
      MACAddress       : 02:13:EF:F3:6F:F5
      AdapterType      : Ethernet 802.3
      DeviceID         : 17
      Name             : Microsoft Wi-Fi Direct Virtual Adapter #2
      NetworkAddresses : 
      Speed            : 9223372036854775807
  #>
  Param([string]$ComputerName = $env:COMPUTERNAME)
  Get-WmiObject -ComputerName $ComputerName -Class Win32_NetworkAdapter |
  Where-Object { $_.Name -match 'wi-fi|wireless' }
}