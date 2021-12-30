function ConvertFrom-Base64 {
    param([Parameter(Mandatory, ValueFromPipeline)]$String)
    [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($String))
}

function ConvertTo-Base64 {
    param([Parameter(Mandatory, ValueFromPipeline)]$String)
    $Bytes = [System.Text.Encoding]::Unicode.GetBytes($String)
    [Convert]::ToBase64String($Bytes)
}

function ConvertTo-BinaryString {
    Param([IPAddress]$IpAddress)
    $Integer = $IpAddress.Address
    $ReverseIpAddress = [IPAddress][String]$Integer
    $BinaryString = [Convert]::toString($ReverseIpAddress.Address,2)
    return $BinaryString
}

function ConvertTo-IpAddress {
    Param($BinaryString)
    $Integer = [System.Convert]::ToInt64($BinaryString,2).ToString()
    $IpAddress = ([System.Net.IPAddress]$Integer).IpAddressToString
    return $IpAddress
}

filter Read-WinEvent {
    $XmlData = [xml]$_.ToXml()
    $Event = New-Object -TypeName PSObject
    $Event = New-Object -TypeName PSObject
    $Event | Add-Member -MemberType NoteProperty -Name LogName -Value $XmlData.Event.System.Channel
    $Event | Add-Member -MemberType NoteProperty -Name EventId -Value $XmlData.Event.System.EventId
    $Event | Add-Member -MemberType NoteProperty -Name TimeCreated -Value $_.TimeCreated
    $Event | Add-Member -MemberType NoteProperty -Name Hostname -Value $XmlData.Event.System.Computer
    $Event | Add-Member -MemberType NoteProperty -Name RecordId -Value $XmlData.Event.System.EventRecordId
    if ($XmlData.Event.System.Security.UserId) {
        $Event | Add-Member -MemberType NoteProperty -Name SecurityUserId -Value $XmlData.Event.System.Security.UserId
    }
    $EventData = $XmlData.Event.EventData.Data
    for ($Property = 0; $Property -lt $EventData.Count; $Property++) {
        $Event | Add-Member -MemberType NoteProperty -Name $EventData[$Property].Name -Value $EventData[$Property].'#text'
    }
    return $Event
}