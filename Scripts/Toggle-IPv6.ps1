Param(
    [switch]$Off,
    [switch]$On
)

function Turn-OffIPv6 {
    $Modified = @()
    Get-NetAdapterBinding -ComponentID ms_tcpip6 | ForEach-Object { 
        if ($_.Enabled -eq $true) {
            $NetworkCard = $_.Name
            Disable-NetAdapterBinding -Name $NetworkCard -ComponentID ms_tcpip6
            $Modified += $NetworkCard
        } 
    }
    if ($Modified.Count -gt 0) {
        $Message = "[+] $env:COMPUTERNAME - Disabled (IPv6): " + ($Modified -join ', ')
        Write-Host $Message
    }
}

function Turn-OnIPv6 {
    $Modified = @()
    Get-NetAdapterBinding -ComponentID ms_tcpip6 | ForEach-Object { 
        if ($_.Enabled -eq $false) {
            $NetworkCard = $_.Name
            Enable-NetAdapterBinding -Name $NetworkCard -ComponentID ms_tcpip6
            $Modified += $NetworkCard
        } 
    }
    if ($Modified.Count -gt 0) {
        $Message = "[+] $env:COMPUTERNAME - Enabled (IPv6): " + ($Modified -join ', ')
        Write-Host $Message
    }
}

function Main {
    if ($Off) {
        Turn-OffIPv6
    } elseif ($On) {
        Turn-OnIPv6
    } else {
        Write-Host "[x] No option specified."
    }
}

Main

# REFERENCES
# https://www.tenforums.com/tutorials/90033-enable-disable-ipv6-windows.html
