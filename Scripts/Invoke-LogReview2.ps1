Param(
    [switch]$PowerShell
)

function Get-Credentials {
    $UserId = [Security.Principal.WindowsIdentity]::GetCurrent()
    $AdminId = [Security.Principal.WindowsBuiltInRole]::Administrator
    $CurrentUser = New-Object Security.Principal.WindowsPrincipal($UserId)
    $RunningAsAdmin = $CurrentUser.IsInRole($AdminId)
    if (-not $RunningAsAdmin) { 
        Write-Output "`n[x] This script requires administrator privileges.`n"
        break
    }
}

function Get-PowerShell {
    $SearchCriteria = @{ 
        LogName = 'Security','Microsoft-Windows-PowerShell/Operational'
        #StartTime = (Get-Date).AddDays(-3);
        #EndTime = (Get-Date);
        Id = 4103,4688;
    }

    Get-WinEvent -FilterHashtable $SearchCriteria | 
    ForEach-Object {
        if ($_.Id -eq '4103') {
            $XmlData = [xml]$_.ToXml()
            $ParentProcessName = ($XmlData.Event.EventData.Data[0].'#text' -split "`n")[4].Split("=")[1].TrimStart()
            $PowerShellVersion = ($XmlData.Event.EventData.Data[0].'#text' -split "`n")[5].Split("=")[1].TrimStart()
            $Command = ($XmlData.Event.EventData.Data[0].'#text' -split "`n")[8].Split("=")[1].TrimStart()
            $Script = ($XmlData.Event.EventData.Data[0].'#text' -split "`n")[10].Split("=")[1].TrimStart()
            $UserName = ($XmlData.Event.EventData.Data[0].'#text' -split "`n")[13].Split("=")[1].TrimStart()

            $Event = New-Object -TypeName psobject
            Add-Member -InputObject $Event -MemberType NoteProperty -Name TimeCreated -Value $_.TimeCreated
            Add-Member -InputObject $Event -MemberType NoteProperty -Name HostName -Value $HostName
            Add-Member -InputObject $Event -MemberType NoteProperty -Name RecordId -Value $_.RecordId
            Add-Member -InputObject $Event -MemberType NoteProperty -Name EventId -Value $_.Id 
            Add-Member -InputObject $Event -MemberType NoteProperty -Name ProcessId -Value $_.ProcessId
            Add-Member -InputObject $Event -MemberType NoteProperty -Name UserName -Value $UserName
            Add-Member -InputObject $Event -MemberType NoteProperty -Name Sid -Value $_.UserId
            Add-Member -InputObject $Event -MemberType NoteProperty -Name ParentProcessName -Value $ParentProcessName
            Add-Member -InputObject $Event -MemberType NoteProperty -Name Command -Value $Command
            Add-Member -InputObject $Event -MemberType NoteProperty -Name PowerShellVersion -Value $PowerShellVersion
            Add-Member -InputObject $Event -MemberType NoteProperty -Name Script -Value $Script
            return $Event
        } elseif ($_.Id -eq '4688') {
            $XmlData = [xml]$_.ToXml()
            $NewProcessName = $XmlData.Event.EventData.Data[5].'#text'
            $ParentProcessName = $XmlData.Event.EventData.Data[13].'#text'
 
            if (($NewProcessName -like '*powershell*') -or ($ParentProcessName -like '*powershell*')) {
                $Event = New-Object -TypeName psobject
                Add-Member -InputObject $Event -MemberType NoteProperty -Name TimeCreated -Value $_.TimeCreated
                Add-Member -InputObject $Event -MemberType NoteProperty -Name HostName -Value $HostName
                Add-Member -InputObject $Event -MemberType NoteProperty -Name RecordId -Value $_.RecordId
                Add-Member -InputObject $Event -MemberType NoteProperty -Name EventId -Value $_.Id 
                Add-Member -InputObject $Event -MemberType NoteProperty -Name ProcessId -Value $XmlData.Event.EventData.Data[7].'#text'
                Add-Member -InputObject $Event -MemberType NoteProperty -Name UserName -Value $XmlData.Event.EventData.Data[1].'#text'
                Add-Member -InputObject $Event -MemberType NoteProperty -Name Sid -Value $XmlData.Event.EventData.Data[0].'#text'
                Add-Member -InputObject $Event -MemberType NoteProperty -Name ParentProcessName -Value $ParentProcessName
                Add-Member -InputObject $Event -MemberType NoteProperty -Name Command -Value $XmlData.Event.EventData.Data[8].'#text'
                Add-Member -InputObject $Event -MemberType NoteProperty -Name PowerShellVersion -Value '-'
                Add-Member -InputObject $Event -MemberType NoteProperty -Name Script -Value '-'
                return $Event
            }
        }
    } 
}

function New-LogReview {
    $HostName = $env:COMPUTERNAME
    if ($PowerShell) { Get-PowerShell }
}

Get-Credentials
New-LogReview | 
Select TimeCreated,HostName,RecordId,EventId,UserName,Sid |
Format-Table -AutoSize

<#
REFERENCES
https://social.technet.microsoft.com/Forums/scriptcenter/en-US/2a3abb64-a686-4664-a08f-5a425da831bc/parsing-of-message-field-of-event-log-entry-using-powershell?forum=ITCG
https://powershell.org/forums/topic/get-info-from-an-eventlog-message-generaldetails-pane/
https://community.spiceworks.com/how_to/137203-create-an-excel-file-from-within-powershell
https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-7.1
https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4624
https://stackoverflow.com/questions/42260709/powershell-separate-and-parse-multiline-string
#>
