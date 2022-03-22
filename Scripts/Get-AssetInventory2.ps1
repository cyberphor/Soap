Param(
    $ComputerName
)

function Get-AssetInventory {
    $Assets = @()
    if (Test-Path $ComputerName) {
        Get-Content $ComputerName |
        ForEach-Object {
            $Online = Test-Connection -Count 2 -ComputerName $_ -ErrorAction SilentlyContinue
            if ($Online) {
                if ("$_" -as [IPAddress] -as [Bool]) {
                    # ip address
                    $IpAddress = $_

                    # mac address
                    $ArpCache = Get-NetNeighbor | 
                    Where-Object { $_.IPAddress -eq "$IpAddress"} | 
                    Select -ExpandProperty LinkLayerAddress 
                    $MacAddress = ([regex]::split("$ArpCache", '(.{2})') | 
                    Where-Object { $_ }) -join '-'

                    # os
                    $OS = $Online | Select -ExpandProperty TimeToLive

                    # hostname
                    $Hostname = ''

                    # serial number
                    $SerialNumber = ''

                    # user
                    $CurrentUser = ''
                }
            
                $Asset = New-Object -TypeName PSObject
                Add-Member -InputObject $Asset -MemberType NoteProperty -Name Online -Value $Online 
                Add-Member -InputObject $Asset -MemberType NoteProperty -Name IpAddress -Value $IpAddress
                Add-Member -InputObject $Asset -MemberType NoteProperty -Name MacAddress -Value $MacAddress
                Add-Member -InputObject $Asset -MemberType NoteProperty -Name Hostname -Value $Hostname
                Add-Member -InputObject $Asset -MemberType NoteProperty -Name SerialNumber -Value $SerialNumber
                Add-Member -InputObject $Asset -MemberType NoteProperty -Name CurrentUser -Value $CurrentUser
                $Assets += $Asset
            } 
        }
    } else {
        $Targets = $ComputerName
    }

    $Assets | ForEach-Object {
        $Online = $_.Online
        $IpAddress = $_.IpAddress
        $MacAddress = $_.MacAddress
        $Hostname = $_.Hostname
        $SerialNumber = $_.SerialNumber
        $CurrentUser = $_.CurrentUser 
        if ($Online) {
            Write-Host "[+] $IpAddress, $MacAddress, $Hostname, $SerialNumber, $CurrentUser"
        } else {
            Write-Host "[x] $IpAddress, $MacAddress, $Hostname, $SerialNumber, $CurrentUser"
        }
    }
}

function Main {
    if ($ComputerName) {
        Get-AssetInventory 
    } else { 
        Write-Host "[x] No machines specified."
        exit
    }
}

Main

# REFERENCES
# https://stackoverflow.com/questions/16360019/how-do-i-add-multi-threading
# https://stackoverflow.com/questions/15120597/passing-multiple-values-to-a-single-powershell-script-parameter
# https://stackoverflow.com/questions/13264369/how-to-pass-array-of-arguments-to-powershell-commandline
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/start-job?view=powershell-7
# https://ridicurious.com/2018/11/14/4-ways-to-validate-ipaddress-in-powershell/
# https://sqljana.wordpress.com/2015/08/25/get-operating-system-name-linux-unix-windows-using-powershell/
# https://docs.microsoft.com/en-us/powershell/module/nettcpip/get-netneighbor?view=win10-ps
