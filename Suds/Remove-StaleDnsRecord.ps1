function Remove-StaleDnsRecord {
  <#
      .LINK
      https://adamtheautomator.com/powershell-dns/
  #>
  $Domain = (Get-AdDomain).Forest
  $30DaysAgo = (Get-Date).AddDays(-30)
  Get-DnsServerResourceRecord -Zone $Domain -RRType A | 
  Where-Object { $_.TimeStamp -le $30DaysAgo } | 
  Remove-DnsServerResourceRecord -ZoneName $Domain -Force
}