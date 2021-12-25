filter Read-WinEvent {
    $XmlData = [xml]$_.ToXml()
    $Event = New-Object -TypeName PSObject
    $SystemData = $XmlData.Event.System
    ($SystemData | Get-Member -MemberType Properties).Name |
    ForEach-Object {
        $Property = $_
        if ($SystemData[$Property].'#text') {
            $Event | Add-Member -MemberType NoteProperty -Name $Property -Value $SystemData[$Property].'#text' 
        } else {
            $SystemData[$Property] | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name |
            ForEach-Object {
                $Event | Add-Member -MemberType NoteProperty -Name $_ -Value $SystemData[$Property].$_ 
            }
        }
    }
    $EventData = $XmlData.Event.EventData.Data
    for ($Property = 0; $Property -lt $EventData.Count; $Property++) {
        $Event | Add-Member -MemberType NoteProperty -Name $EventData[$Property].Name -Value $EventData[$Property].'#text'
    }
    return $Event
}

function Update-AdDescriptionWithLastLogon {
    
}

