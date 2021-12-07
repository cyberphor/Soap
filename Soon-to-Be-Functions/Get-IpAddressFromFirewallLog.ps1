function Get-IpAddressFromFirewallLog {
    $IpAddress = ""
    $SearchCriteria = @{
      LogName = "Security";
      Id = 5156;
      StartTime = (Get-Date).AddDays(-3);
      EndTime = (Get-Date);
    }
  
    Get-WinEvent -FilterHashTable $SearchCriteria | 
    foreach {
        $Event = [xml]$_.ToXml()
        $RemoteIpAddress = $Event.Event.EventData.Data[5].'#text'
        if ($RemoteIpAddress -like $IpAddress) {
            $Username = (Get-WmiObject -Class Win32_NetworkLoginProfile | 
                Where-Object { $_.Name -notlike "*admin*" -and $_.Name -notlike "*service*" } |
                Sort-Object -Property LastLogon -Descending |
                Select-Object -First 1 -ExpandProperty Name).Split("\")[1]
            $Model = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model
            $SerialNumber = Get-WmiObject -Class Win32_BIOS | Select-Object -ExpandProperty SerialNumber
            $ComputerInformation = New-Object psobject
            Add-Member -InputObject $ComputerInformation -MemberType NoteProperty -Name Hostname -Value $Hostname
            Add-Member -InputObject $ComputerInformation -MemberType NoteProperty -Name Username -Value $Username
            Add-Member -InputObject $ComputerInformation -MemberType NoteProperty -Name Model -Value $Model
            Add-Member -InputObject $ComputerInformation -MemberType NoteProperty -Name SerialNumber -Value $SerialNumber
            Add-Member -InputObject $ComputerInformation -MemberType NoteProperty -Name LogRecordId -Value $_.RecordId
            $ComputerInformation
            break
        }
    }
}

Get-IpAddressFromFirewallLog
