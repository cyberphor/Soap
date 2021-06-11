function Get-Asset {
    $IpAddress = (Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled" = 'True' |
        Select-Object -Property *).IpAddress[0]
    $SystemInfo = Get-ComputerInfo
    
    $Asset = New-Object psobject
    Add-Member -InputObject $Asset -MemberType NoteProperty -Name IpAddress -Value $IpAddress
    Add-Member -InputObject $Asset -MemberType NoteProperty -Name Hostname -Value $env:COMPUTERNAME
    Add-Member -InputObject $Asset -MemberType NoteProperty -Name Version -Value $SystemInfo.OsVersion
    Add-Member -InputObject $Asset -MemberType NoteProperty -Name Make -Value $SystemInfo.CsManufacturer
    Add-Member -InputObject $Asset -MemberType NoteProperty -Name Model -Value $SystemInfo.CsModel
    Add-Member -InputObject $Asset -MemberType NoteProperty -Name SerialNumber Value $SystemInfo.BiosSerialNumber
    Add-Member -InputObject $Asset -MemberType NoteProperty -Name Architecture -Value $SystemInfo.OsArchitecture
    Add-Member -InputObject $Asset -MemberType NoteProperty -Name OperatingSystem -Value $SystemInfo.OsName
    $Asset
}

Get-Asset
