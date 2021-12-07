function Unblock-TrafficToIpAddress {
  $IpAddress = ""
  Remove-NetFirewall -DisplayName "Incident Response: Block $IpAddress"
}

Unblock-TrafficToIpAddress
