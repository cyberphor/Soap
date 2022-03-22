<#
.SYNOPSIS
    Ships "Forwarded Events" as JSON objects over HTTP to a SIEM server. 
.DESCRIPTION
    See SYNOPSIS.
.EXAMPLES
    ./Ship-WinEvents.ps1 -LogName Application
    ./Ship-WinEvents.ps1 -Address 192.168.1.9
    ./Ship-WinEvents.ps1 -Port 8000
    ./Ship-WinEvents.ps1 -LogName System -Address 192.168.1.10 -Port 4444
.INPUTS
    Windows Event logs found under the "C:\Windows\System32\winevt\Logs\" directory. 
.OUTPUTS
    Creates two files in your current working directory:
        - (1) ".\EventsShippedAlready.txt"
        - (2) ".\ScriptLog.txt"
.LINK
    https://www.yoursecurity.tech
.NOTES
    File name: Ship-WinEvents.ps1
    Version: 2.0
    Author: Victor Fernandez III
    Creation Date: Wednesday, January 1st, 2020
    Purpose: Ship "Forwarded Events" as JSON objects over HTTP to a SIEM server.
#>

Param(
    [ValidateScript({Get-WinEvent -LogName $_ -MaxEvents 1})]
    [string]$LogName = 'ForwardedEvents',

    [ValidateScript({Test-Connection -ComputerName $_ -Count 2 -Quiet})]
    [ipaddress]$Address = '192.168.1.9',

    [ValidateScript({New-Object System.Net.Sockets.TcpClient($Address, $_)})]
    [int]$Port = '8000'
)

function SendTo-ScriptLog {
    Param([Parameter(ValueFromPipeline)]$Message)
    $Message | Tee-Object -FilePath ".\ScriptLog.txt" -Append 
}

$Server = ('http://' + $Address + ':' + $Port).ToString()
$Receipts = ".\EventsAlreadyShipped.txt"
$KeepingReceipts = Test-Path -Path $Receipts
$AddToReceipts = @()

While ($true) {

    if (-not $KeepingReceipts) { 
        New-Item -Type File -Name $Receipts | Out-Null 
        Write-Output "[!] $(Get-Date) - Created shipment log: $Receipts" | SendTo-ScriptLog
    } 

    $Shipments = Get-Content $Receipts -ReadCount 1000 | ConvertFrom-Csv

    Get-WinEvent -LogName $LogName |
    ForEach-Object {
        [System.GC]::Collect()
        $Receipt = $_ | Select-Object MachineName, RecordId, Id
    
        $Shipped = $Shipments | Where-Object { 
            ($_.MachineName -eq $Receipt.MachineName) -and 
            ($_.RecordId -like $Receipt.RecordId) -and 
            ($_.Id -eq $Receipt.Id)
        }

        if (-not $Shipped) {  
            try {
                $ParsedMessage = @{}
                $_.Message -split '\r\n' -replace '\t','' | 
                    ForEach-Object { 
                        $key,$value = $_.Split(':')
                        if ($key -and $value -ne $null) {
                            $ParsedMessage[$key] = $value
                        }
                    }
                $_.Message = $ParsedMessage
                $Data = $_ | ConvertTo-Json -Compress
                $Time = ($_.TimeCreated | Get-Date -Format "o" | Out-String)
                $Event = $Data -replace "\\/Date\(\d+\)\\/", $Time.Trim() 
                $ServerResponse = Invoke-WebRequest -Method Post -Uri $Server -Body $Event
                $Receipt | ConvertTo-Csv | Out-File -Append $Receipts
                Write-Output "[+] $(Get-Date) - Shipped event: $Receipt"
            } catch {
                Write-Output "[x] $(Get-Date) - Failed to ship event to SIEM server." | SendTo-ScriptLog
                break    
            }
        } 
    }

    Write-Output "[+] $(Get-Date) - Shipped events." | SendTo-ScriptLog
    Start-Sleep -Seconds 60
}

<#
### PUT THESE FILES ON YOUR SIEM ###

## nc_webserver.sh ##
while true; do echo -e $(<./index.html) | nc -nvlp 8000 | sed '1,5d' >> /var/log/windows/events.log; done

## index.html ##
HTTP/1.1 200 OK
\r\nDate: Wed, 1 Jan 2020 00:00:00 GMT
\r\nServer: Netcat
\r\nContent-Type: text/html
\r\nContent-Length: 6
\r\nConnection: close
\r\n\r\nThanks
#>
