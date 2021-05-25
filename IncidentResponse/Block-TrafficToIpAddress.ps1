function Block-TrafficToIpAddress {
  $IpAddress = ""
  New-NetFirewall -DisplayName "Incident Response: Block $IpAddress" -Direction Outbound -Action Block -RemoteAddress $IpAddress
}

Block-TrafficToIpAddress
