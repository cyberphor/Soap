$NetworkID = "10.10.10."
$Assets = @()

1..254 | 
ForEach-Object {
    $IpAddress = $NetworkID + $_
    if (Test-Connection $IpAddress -Count 1 -Quiet) {
        Write-Host "[+] ONLINE: $IpAddress" -BackgroundColor Green -ForegroundColor Black 
        $Asset = New-Object psobject
        $ComputerSystem = Get-WmiObject -ComputerName $IpAddress -Class Win32_ComputerSystem
        $Hostname = $ComputerSystem.Name
        $MacAddress = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | 
            Where-Object { $_.IpAddress -eq $IpAddress } | 
            Select -ExpandProperty MacAddress
        $SerialNumber = (Get-WmiObject -Class Win32_BIOS).SerialNumber
        $Manufacturer = $ComputerSystem.Manufacturer
        $Model = $ComputerSystem.Model
        $Username = ((Get-WmiObject -Class Win32_ComputerSystem).UserName -split '\\')[1]

        Add-Member -InputObject $Asset -MemberType NoteProperty -Name IpAddress -Value $IpAddress
        Add-Member -InputObject $Asset -MemberType NoteProperty -Name Hostname -Value $Hostname
        Add-Member -InputObject $Asset -MemberType NoteProperty -Name MacAddress -Value $MacAddress
        Add-Member -InputObject $Asset -MemberType NoteProperty -Name SerialNumber -Value $SerialNumber
        Add-Member -InputObject $Asset -MemberType NoteProperty -Name Manufacturer -Value $Manufacturer
        Add-Member -InputObject $Asset -MemberType NoteProperty -Name Model -Value $Model  
        Add-Member -InputObject $Asset -MemberType NoteProperty -Name Username -Value $Username          
        $Assets += $Asset
    } else { 
        Write-Host "[+] OFFLINE: $IpAddress" -BackgroundColor Red -ForegroundColor Black
    }
}

Clear-Host
$Assets | Format-Table
