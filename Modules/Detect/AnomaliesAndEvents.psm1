function Get-Indicator {
    param(
        [string]$Path = "C:\Users",
        [Parameter(Mandatory)][string]$FileName
    )
    Get-ChildItem -Path $Path -Recurse -Force -ErrorAction Ignore |
    Where-Object { $_.Name -like $FileName } |
    Select-Object -ExpandProperty FullName
}

function Invoke-WinEventParser {
    param(
        [Parameter(Position=0)][string]$ComputerName,
        [ValidateSet("Application","Security","System","ForwardedEvents","Microsoft-Windows-PowerShell/Operational")][Parameter(Position=1)][string]$LogName,
        [ValidateSet("4104","4624","4625","4663","4672","4688","4697","5140","5156","6416")][Parameter(Position=2)]$EventId,
        [Parameter(Position=3)][int]$DaysAgo=1,
        [Parameter(Position=4)][switch]$TurnOffOutputFilter
    )
    if ($TurnOffOutputFilter) {
        Get-WinEvent -FilterHashtable @{ LogName=$LogName; Id=$EventId } |
        Read-WinEvent
    } else {
        if ($EventId -eq "4104") { $Properties = "TimeCreated","SecurityUserId","ScriptBlockText" }
        elseif ($EventId -eq "4624") { $Properties = "TimeCreated","IpAddress","TargetUserName","LogonType" }
        elseif ($EventId -eq "4625") { $Properties = "TimeCreated","IpAddress","TargetUserName","LogonType" }
        elseif ($EventId -eq "4663") { $Properties = "*" }
        elseif ($EventId -eq "4672") { $Properties = "TimeCreated","SubjectUserSid","SubjectUserName" }
        elseif ($EventId -eq "4688") { $Properties = "TimeCreated","TargetUserName","NewProcessName","CommandLine" }
        elseif ($EventId -eq "4697") { $Properties = "*" }
        elseif ($EventId -eq "5140") { $Properties = "*" }
        elseif ($EventId -eq "5156") { $Properties = "TimeCreated","SourceAddress","DestAddress","DestPort" }
        elseif ($EventId -eq "6416") { $Properties = "TimeCreated","SubjectUserName","ClassName","DeviceDescription" }
        else { $Properties = "*" }
        Get-WinEvent -FilterHashtable @{ LogName=$LogName; Id=$EventId } |
        Read-WinEvent |
        Select-Object -Property $Properties
    }
}