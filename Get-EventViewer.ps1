filter Read-WinEvent {
        $WinEvent = [ordered]@{} 
        $XmlData = [xml]$_.ToXml()
        $SystemData = $XmlData.Event.System
        $SystemData | 
        Get-Member -MemberType Properties | 
        Select-Object -ExpandProperty Name |
        ForEach-Object {
            $Field = $_
            if ($Field -eq 'TimeCreated') {
                $WinEvent.$Field = Get-Date -Format 'yyyy-MM-dd hh:mm:ss' $SystemData[$Field].SystemTime
            } elseif ($SystemData[$Field].'#text') {
                $WinEvent.$Field = $SystemData[$Field].'#text'
            } else {
                $SystemData[$Field]  | 
                Get-Member -MemberType Properties | 
                Select-Object -ExpandProperty Name |
                ForEach-Object { 
                    $WinEvent.$Field = @{}
                    $WinEvent.$Field.$_ = $SystemData[$Field].$_
                }
            }
        }
        $XmlData.Event.EventData.Data |
        ForEach-Object { 
            $WinEvent.$($_.Name) = $_.'#text'
        }
        return New-Object -TypeName PSObject -Property $WinEvent
}

# create a COM object for Excel
$Excel = New-Object -ComObject Excel.Application

# create a workbook and then add two worksheets to it
$Workbook = $Excel.Workbooks.Add()
$Tab2 = $Workbook.Worksheets.Add()
$Tab3 = $Workbook.Worksheets.Add()

function Get-SuccessfulLogonEvents {
    # rename the first worksheet 
    $Workbook.Worksheets.Item(1).Name = "SuccessfulLogon"

    # define column headers using the first row
    $Workbook.Worksheets.Item("SuccessfulLogon").Cells.Item(1,1) = "TimeCreated"
    $Workbook.Worksheets.Item("SuccessfulLogon").Cells.Item(1,2) = "RecordId"
    $Workbook.Worksheets.Item("SuccessfulLogon").Cells.Item(1,3) = "UserName"
    $Workbook.Worksheets.Item("SuccessfulLogon").Cells.Item(1,4) = "LogonType"
    
    # define where to begin adding data (by row and column)
    $rTimeCreated, $cTimeCreated = 2,1
    $rRecordId, $cRecordId = 2,2
    $rUserName, $cUserName = 2,3
    $rLogonType, $cLogonType = 2,4

    # define what Windows Event criteria must match 
    $FilterHashTable = @{
        LogName = "Security"
        Id = 4624
        StartTime = $(Get-Date).AddDays(-3)
    }

    # cycle through the Windows Events that match the criteria above
    Get-WinEvent -FilterHashtable $FilterHashTable |
    Read-WinEvent |
    Select-Object -Property TimeCreated,EventRecordId,TargetUserName,LogonType |
    Where-Object { 
        $_.TargetUserName -ne "SYSTEM" 
    } |
    ForEach-Object {
        [System.GC]::Collect()
        # fill-in the current row
        $Workbook.Worksheets.Item("SuccessfulLogon").Cells.Item($rTimeCreated, $cTimeCreated) = $_.TimeCreated
        $Workbook.Worksheets.Item("SuccessfulLogon").Cells.Item($rRecordId, $cRecordId) = $_.EventRecordId
        $Workbook.Worksheets.Item("SuccessfulLogon").Cells.Item($rUserName, $cUserName) = $_.TargetUserName
        $Workbook.Worksheets.Item("SuccessfulLogon").Cells.Item($rLogonType, $cLogonType) = $_.LogonType

        # move-on to the next row
        $rTimeCreated++
        $rRecordId++
        $rUserName++
        $rLogonType++
    }
}

function Get-ProcessCreationEvents {
    # rename the second worksheet 
    $Workbook.Worksheets.Item(2).Name = "ProcessCreation"

    # define column headers using the first row
    $Workbook.Worksheets.Item("ProcessCreation").Cells.Item(1,1) = "TimeCreated"
    $Workbook.Worksheets.Item("ProcessCreation").Cells.Item(1,2) = "RecordId"
    $Workbook.Worksheets.Item("ProcessCreation").Cells.Item(1,3) = "UserName"
    $Workbook.Worksheets.Item("ProcessCreation").Cells.Item(1,4) = "ParentProcessName"
    $Workbook.Worksheets.Item("ProcessCreation").Cells.Item(1,5) = "CommandLine"
    
    # define where to begin adding data (by row and column)
    $rTimeCreated, $cTimeCreated = 2,1
    $rRecordId, $cRecordId = 2,2
    $rUserName, $cUserName = 2,3
    $rParentProcessName, $cParentProcessName = 2,4
    $rCommandLine, $cCommandLine = 2,5

    # define what Windows Event criteria must match 
    $FilterHashTable = @{
        LogName = "Security"
        Id = 4688
        StartTime = $(Get-Date).AddDays(-3)

    }

    # cycle through the Windows Events that match the criteria above
    Get-WinEvent -FilterHashtable $FilterHashTable |
    Read-WinEvent |
    Select-Object -Property TimeCreated,EventRecordId,TargetUserName,ParentProcessName,CommandLine |
    Where-Object { 
        ($_.TargetUserName -ne "-") -and `
        ($_.TargetUserName -notlike "*$") -and `
        ($_.TargetUserName -ne "LOCAL SERVICE")
    } |
    ForEach-Object {
        [System.GC]::Collect()
        # fill-in the current row
        $Workbook.Worksheets.Item("ProcessCreation").Cells.Item($rTimeCreated, $cTimeCreated) = $_.TimeCreated
        $Workbook.Worksheets.Item("ProcessCreation").Cells.Item($rRecordId, $cRecordId) = $_.EventRecordId
        $Workbook.Worksheets.Item("ProcessCreation").Cells.Item($rUserName, $cUserName) = $_.TargetUserName
        $Workbook.Worksheets.Item("ProcessCreation").Cells.Item($rParentProcessName, $cParentProcessName) = $_.ParentProcessName
        $Workbook.Worksheets.Item("ProcessCreation").Cells.Item($rCommandLine, $cCommandLine) = $_.CommandLine

        # move-on to the next row
        $rTimeCreated++
        $rRecordId++
        $rUserName++
        $rParentProcessName++
        $rCommandLine++
    }
}

function Get-PowerShellEvents {
    # rename the third worksheet 
    $Workbook.Worksheets.Item(3).Name = "PowerShell"

    # define column headers using the first row
    $Workbook.Worksheets.Item("PowerShell").Cells.Item(1,1) = "TimeCreated"
    $Workbook.Worksheets.Item("PowerShell").Cells.Item(1,2) = "RecordId"
    $Workbook.Worksheets.Item("PowerShell").Cells.Item(1,3) = "Sid"
    $Workbook.Worksheets.Item("PowerShell").Cells.Item(1,4) = "ScriptBlockText"
    
    # define where to begin adding data (by row and column)
    $rTimeCreated, $cTimeCreated = 2,1
    $rRecordId, $cRecordId = 2,2
    $rSid, $cSid = 2,3
    $rScriptBlockText, $cScriptBlockText = 2,4

    # define what Windows Event criteria must match 
    $FilterHashTable = @{
        LogName = "Microsoft-Windows-PowerShell/Operational"
        Id = 4104
        StartTime = $(Get-Date).AddDays(-3)
    }

    # cycle through the Windows Events that match the criteria above
    Get-WinEvent -FilterHashtable $FilterHashTable |
    Read-WinEvent |
    Select-Object -Property TimeCreated,EventRecordId,@{N="Sid";E={$_.Security.UserId}},ScriptBlockText |
    Where-Object {
        ($_.Sid -ne "S-1-5-18") -and
        ($_.ScriptBlockText -ne "prompt")
    } |
    ForEach-Object {
        [System.GC]::Collect()
        # fill-in the current row
        $Workbook.Worksheets.Item("PowerShell").Cells.Item($rTimeCreated, $cTimeCreated) = $_.TimeCreated
        $Workbook.Worksheets.Item("PowerShell").Cells.Item($rRecordId, $cRecordId) = $_.EventRecordId
        $Workbook.Worksheets.Item("PowerShell").Cells.Item($rSid, $cSid) = $_.Sid
        $Workbook.Worksheets.Item("PowerShell").Cells.Item($rScriptBlockText, $cScriptBlockText) = $_.ScriptBlockText

        # move-on to the next row
        $rTimeCreated++
        $rRecordId++
        $rSid++
        $rScriptBlockText++
    }
}

$Path = "C:\Users\Victor\Desktop\Events-" + $(Get-Date -Format yyyy-MM-dd_hhmm) +".xlsx"

Get-SuccessfulLogonEvents
$Workbook.Worksheets.Item("SuccessfulLogon").UsedRange.Columns.Autofit()
$Workbook.SaveAs($Path,51)

Get-ProcessCreationEvents
$Workbook.Worksheets.Item("ProcessCreation").UsedRange.Columns.Autofit()
$Workbook.Save()

Get-PowerShellEvents
$Workbook.Worksheets.Item("PowerShell").UsedRange.Columns.Autofit()
$Workbook.Save()

$Excel.Quit()
Invoke-Item -Path $Path
