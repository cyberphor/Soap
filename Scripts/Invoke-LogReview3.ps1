$SearchCriteria = @{
    LogName = 'Security';
    StartTime = (Get-Date).AddDays(-7);
    EndTime = (Get-Date);
    Id = 4624,4647;
}
$Events = @()

Get-WinEvent -FilterHashtable $SearchCriteria |
foreach { 
    $XmlData = [xml]$_.ToXml()

    if ($_.Id -eq '4624') {
        $LogonType = $XmlData.Event.EventData.Data[8].'#text'

        if ($LogonType -eq '2') {
            $Username = $XmlData.Event.EventData.Data[5].'#text'
            $LogonId = $XmlData.Event.EventData.Data[7].'#text'

            $Event = New-Object -TypeName psobject
            Add-Member -InputObject $Event -MemberType NoteProperty -Name TimeCreated -Value $_.TimeCreated
            Add-Member -InputObject $Event -MemberType NoteProperty -Name RecordId -Value $_.RecordId
            Add-Member -InputObject $Event -MemberType NoteProperty -Name Username -Value $Username
            Add-Member -InputObject $Event -MemberType NoteProperty -Name LogonType -Value $LogonType
            Add-Member -InputObject $Event -MemberType NoteProperty -Name LogonId -Value $LogonId
            $Events += $Event
        }
    }
    
    if ($_.Id -eq '4647') {
        $LogonId = $XmlData.Event.EventData.Data[3].'#text'
    }
}

$Events | Format-Table -AutoSize
