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
    if ($_ -and $_.GetType().Name -eq 'EventLogRecord') {
        $XmlData = [xml]$_.ToXml()
        $Event = New-Object -TypeName PSObject
        $SystemData = $XmlData.Event.System
        ($SystemData | Get-Member -MemberType Properties).Name |
        ForEach-Object {
            $ParentProperty = $_
            if ($SystemData[$ParentProperty].'#text') {
                $Event | Add-Member -MemberType NoteProperty -Name $ParentProperty -Value $SystemData[$ParentProperty].'#text' 
            } else {
                $SystemData[$ParentProperty] | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name |
                ForEach-Object {
                    $ChildProperty = $ParentProperty + $_ 
                    $Event | Add-Member -MemberType NoteProperty -Name $ChildProperty -Value $SystemData[$ParentProperty].$_ 
                }
            }
        }
        $EventData = $XmlData.Event.EventData.Data
        for ($Property = 0; $Property -lt $EventData.Count; $Property++) {
            $Event | Add-Member -MemberType NoteProperty -Name $EventData[$Property].Name -Value $EventData[$Property].'#text'
        }
        return $Event
    } else {
        Write-Error -Message "The input object type must EventLogRecord."
    }
}