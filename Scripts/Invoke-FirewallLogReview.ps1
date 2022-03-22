Param(
    [switch]$ExportToCsv
)

function New-FirewallLogReview {
    $Logs = @{ LogName = 'Security'; Id = 5156 }
    Get-WinEvent -FilterHashtable $Logs |
    foreach {
        $XmlData = [xml]$_.ToXml()
        $SourceAddress = $XmlData.Event.EventData.Data[3].'#text'
        $DestinationAddress = $XmlData.Event.EventData.Data[5].'#text'

        if ($Threats -contains $SourceAddress -or $Threats -contains $DestinationAddress) {
            $Event = New-Object -TypeName psobject
            Add-Member -InputObject $Event -MemberType NoteProperty -Name TimeCreated -Value $_.TimeCreated
            Add-Member -InputObject $Event -MemberType NoteProperty -Name RecordId -Value $_.RecordId
            Add-Member -InputObject $Event -MemberType NoteProperty -Name ProcessId -Value $XmlData.Event.EventData.Data[0].'#text'
            Add-Member -InputObject $Event -MemberType NoteProperty -Name Protocol -Value $XmlData.Event.EventData.Data[7].'#text'
            Add-Member -InputObject $Event -MemberType NoteProperty -Name SourceAddress -Value $SourceAddress
            Add-Member -InputObject $Event -MemberType NoteProperty -Name SourcePort -Value $XmlData.Event.EventData.Data[4].'#text'
            Add-Member -InputObject $Event -MemberType NoteProperty -Name DestinationPort -Value $XmlData.Event.EventData.Data[6].'#text'
            Add-Member -InputObject $Event -MemberType NoteProperty -Name DestinationAddress -Value $DestinationAddress
            return $Event
        }
    } 
}

function Get-CyberThreatIntel {
    #$DateSource = 'http://rules.emergingthreats.net/blockrules/compromised-ips.txt'
    #$Threats = (Invoke-WebRequest -Uri $DataSource -ErrorAction Ignore).Content
    $Threats = Get-Content C:\Users\Public\Documents\Scripts\compromised-ips.txt
}

Get-CyberThreatIntel

if ($ExportToCsv) {
    $Computer = (Get-WmiObject -Class Win32_ComputerSystem).Name + '_'
    $Date = Get-Date -Format yyyy-MM-dd_HHMM
    $Dropbox = 'C:\Users\Public\'
    $Folder = $Dropbox + 'Firewall\'
    $File = $Folder + 'Firewall_' + $Computer + $Date + '.csv'

    if (-not(Test-Path $Dropbox)) {
        New-Item -ItemType Directory $Dropbox |
        Out-Null
    }

    if (-not(Test-Path $Folder)) {
        New-Item -ItemType Directory $Folder |
        Out-Null 
    }

    New-FirewallLogReview | 
    Export-Csv -NoTypeInformation -Append -Path $File
} else {
    New-FirewallLogReview |
    Select TimeCreated,RecordId,SourceAddress,DestinationAddress
}

<# REFERENCES
http://rules.emergingthreats.net/blockrules/
#>
