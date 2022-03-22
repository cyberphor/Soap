
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

function Get-BaselineProcessDeviations {

    # Get-Process | Select -ExpandProperty Name | Sort-Object | Get-Unique |
    # ForEach-Object { "'" + $_ + "'," }
    $BaselineProcesses = 
        'ApplicationFrameHost',
        'csrss',
        'ctfmon',
        'dasHost',
        'dllhost',
        'dwm',
        'explorer',
        'fontdrvhost',
        'Idle',
        'jhi_service',
        'LockApp',
        'lsass',
        'Memory Compression',
        'Microsoft.Photos',
        'Registry',
        'RtkAudUService64',
        'RuntimeBroker',
        'SearchIndexer',
        'SearchUI',
        'SecurityHealthService',
        'SecurityHealthSystray',
        'services',
        'SgrmBroker',
        'ShellExperienceHost',
        'smartscreen',
        'smss',
        'spoolsv',
        'svchost',
        'System',
        'SystemSettings',
        'taskhostw',
        'wininit',
        'winlogon'

    Get-Process |
    Sort-Object -Property Name,Id |
    ForEach-Object {
        if ($_.Name -notin $BaselineProcesses) {
            $Process = New-Object -TypeName psobject
            Add-Member -InputObject $Process -MemberType NoteProperty -Name StartTime -Value $_.StartTime
            #Add-Member -InputObject $Port -MemberType NoteProperty -Name Hostname -Value $Hostname
            Add-Member -InputObject $Process -MemberType NoteProperty -Name Id -Value $_.Id
            Add-Member -InputObject $Process -MemberType NoteProperty -Name Name -Value $_.Name
            Add-Member -InputObject $Process -MemberType NoteProperty -Name Path -Value $_.Path
            return $Process
        }
    } 
}

function Get-BaselinePortDeviations {

    #Get-NetTCPConnection | Select -ExpandProperty LocalPort | Sort-Object | Get-Unique |
    #ForEach-Object { "'" + $_ + "'," }
    $BaselinePorts = 
        '135',
        '139',
        '445'

    Get-NetTCPConnection |
    Sort-Object -Property CreationTime |
    ForEach-Object {
        if ($_.LocalPort -notin $BaselinePorts) {
            $Port = New-Object -TypeName psobject
            Add-Member -InputObject $Port -MemberType NoteProperty -Name CreationTime -Value $_.CreationTime
            #Add-Member -InputObject $Port -MemberType NoteProperty -Name Hostname -Value $Hostname
            Add-Member -InputObject $Port -MemberType NoteProperty -Name OwningProcess -Value $_.OwningProcess
            Add-Member -InputObject $Port -MemberType NoteProperty -Name LocalPort -Value $_.LocalPort
            Add-Member -InputObject $Port -MemberType NoteProperty -Name RemotePort -Value $_.RemotePort
            Add-Member -InputObject $Port -MemberType NoteProperty -Name RemoteAddress -Value $_.RemoteAddress
            return $Port
        }
    }
}

function Get-BaselineUserDeviations {

    #Get-WmiObject -Class Win32_UserAccount | Select -ExpandProperty Name 
    #ForEach-Object { "'" + $_ + "'," }
    $BaselineUsers = 
        'Administrator',
        'Guest',
        'Victor'

    Get-WmiObject -Class Win32_UserAccount  |
    ForEach-Object {
        if ($_.Name -notin $BaselineUsers) {
            $User = New-Object -TypeName psobject
            #Add-Member -InputObject $User -MemberType NoteProperty -Name CreationTime -Value $_.CreationTime
            #Add-Member -InputObject $User -MemberType NoteProperty -Name Hostname -Value $Hostname
            Add-Member -InputObject $User -MemberType NoteProperty -Name Name -Value $_.Name
            Add-Member -InputObject $User -MemberType NoteProperty -Name Sid -Value $_.Sid
            return $User
        }
    }
}

function Get-BaselineAdminDeviations {

    #Get-LocalGroupMember -Group "Administrators" | Select -ExpandProperty Name | 
    #ForEach-Object { "'" + ($_).Split('\')[1] + "'," }
    $BaselineAdmins = 
        'Administrator',
        'Elliot'

    Get-LocalGroupMember -Group "Administrators" | 
    ForEach-Object {
        $Name = ($_.Name).Split('\')[1]
        if ($Name -notin $BaselineAdmins) {
            $Admin = New-Object -TypeName psobject
            #Add-Member -InputObject $Admin -MemberType NoteProperty -Name CreationTime -Value $_.CreationTime
            #Add-Member -InputObject $Admin -MemberType NoteProperty -Name Hostname -Value $Hostname
            Add-Member -InputObject $Admin -MemberType NoteProperty -Name Name -Value $_.Name
            Add-Member -InputObject $Admin -MemberType NoteProperty -Name Sid -Value $_.Sid
            return $Admin
        }
    }
}

function Get-BaselineShareDeviations {

    #Get-SmbShare | Select -ExpandProperty Name | 
    #ForEach-Object { "'" + $_ + "'," }
    $BaselineShares = 
        'ADMIN$',
        'C$',
        'IPC$'

    Get-SmbShare | 
    ForEach-Object {
        if ($_.Name -notin $BaselineShares) {
            $Share = New-Object -TypeName psobject
            #Add-Member -InputObject $Share -MemberType NoteProperty -Name CreationTime -Value $_.CreationTime
            #Add-Member -InputObject $Share -MemberType NoteProperty -Name Hostname -Value $Hostname
            Add-Member -InputObject $Share -MemberType NoteProperty -Name Name -Value $_.Name
            Add-Member -InputObject $Share -MemberType NoteProperty -Name Path -Value $_.Path
            return $Share
        }
    }
}

function Get-BaselineServiceDeviations {

    #Get-Service | Select -ExpandProperty Name | Sort-Object | 
    #ForEach-Object { "'" + $_ + "'," }
    $BaselineServices = 
        'AJRouter',
        'ALG',
        'AppIDSvc',
        'Appinfo',
        'AppMgmt',
        'AppReadiness',
        'AppVClient',
        'AppXSvc',
        'AssignedAccessManagerSvc',
        'aswbIDSAgent',
        'AudioEndpointBuilder'

    Get-Service | 
    Sort-Object -Descending -Property Status,Name |
    ForEach-Object {
        if ($_.Name -notin $BaselineServices) {
            $Service = New-Object -TypeName psobject
            #Add-Member -InputObject $Service -MemberType NoteProperty -Name CreationTime -Value $_.CreationTime
            #Add-Member -InputObject $Service -MemberType NoteProperty -Name Hostname -Value $Hostname
            Add-Member -InputObject $Service -MemberType NoteProperty -Name Status -Value $_.Status
            Add-Member -InputObject $Service -MemberType NoteProperty -Name StartType -Value $_.StartType
            Add-Member -InputObject $Service -MemberType NoteProperty -Name Name -Value $_.Name
            Add-Member -InputObject $Service -MemberType NoteProperty -Name DisplayName -Value $_.DisplayName
            return $Service
        }
    }

}

function Get-BaselineAsepDeviations {

    #Get-Item -Path Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run | Select -ExpandProperty Property | 
    #ForEach-Object { "'" + $_ + "'," }
    $BaselineAseps = 
        'SecurityHealth',
        'AvastUI.exe'
    
    'HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce' |
    ForEach-Object {
        $RegistryKey = 'Registry::' + $_
        $TotalNumberOfAseps = (Get-Item $RegistryKey).Property.Count 

        (Get-Item $RegistryKey).Property[0..$TotalNumberOfAseps] |
        ForEach-Object { 
            $App = $_
            $AppPath = (Get-ItemProperty $RegistryKey).$App
            if ($App -notin $BaselineAseps) {
                $Asep = New-Object -TypeName psobject
                #Add-Member -InputObject $Asep -MemberType NoteProperty -Name CreationTime -Value $_.CreationTime
                #Add-Member -InputObject $Asep -MemberType NoteProperty -Name Hostname -Value $Hostname
                Add-Member -InputObject $Asep -MemberType NoteProperty -Name ASEP -Value $App
                Add-Member -InputObject $Asep -MemberType NoteProperty -Name Path -Value $AppPath
                return $Asep
            }
        }
    }
}

function Get-BaselineProgramDeviations {
    
    #Get-WmiObject -Class Win32_Product | Select -ExpandProperty Name | Sort-Object | 
    #ForEach-Object { "'" + $_ + "'," }
    $BaselinePrograms = 
        'Microsoft Access MUI (English) 2013',
        'Microsoft Excel MUI (English) 2013',
        'Microsoft Groove MUI (English) 2013',
        'Microsoft InfoPath MUI (English) 2013',
        'Microsoft Lync MUI (English) 2013',
        'Microsoft Office 32-bit Components 2013'

    Get-WmiObject -Class Win32_Product | 
    Sort-Object -Property Vendor,Name |
    ForEach-Object {
        if ($_.Name -notin $BaselinePrograms) {
            $Program = New-Object -TypeName psobject
            #Add-Member -InputObject $Program -MemberType NoteProperty -Name CreationTime -Value $_.CreationTime
            #Add-Member -InputObject $Program -MemberType NoteProperty -Name Hostname -Value $Hostname
            Add-Member -InputObject $Program -MemberType NoteProperty -Name Vendor -Value $_.Vendor
            Add-Member -InputObject $Program -MemberType NoteProperty -Name Name -Value $_.Name
            Add-Member -InputObject $Program -MemberType NoteProperty -Name Version -Value $_.Version
            return $Program
        }
    }
}

function New-SystemSecurityBaselineAudit {

    $Dropbox = "C:\Users\Public\BaselineAudit"
    $Folder = $Dropbox + "\BaselineAudit_" + $(Get-Date -Format yyyy-MM-dd-HHmm)
    
    if (-not(Test-Path $Dropbox)) {
        New-Item -ItemType Directory $Dropbox  | 
        Out-Null
    }

    if (-not(Test-Path $Folder)) {
        New-Item -ItemType Directory $Folder  | 
        Out-Null
    }

    Get-BaselineProcessDeviations | Export-Csv -NoTypeInformation -Append -Path "$Folder\Processes.csv"
    Get-BaselinePortDeviations | Export-Csv -NoTypeInformation -Append -Path "$Folder\Ports.csv"
    Get-BaselineUserDeviations | Export-Csv -NoTypeInformation -Append -Path "$Folder\Users.csv"
    Get-BaselineAdminDeviations | Export-Csv -NoTypeInformation -Append -Path "$Folder\Admins.csv"
    Get-BaselineShareDeviations | Export-Csv -NoTypeInformation -Append -Path "$Folder\Shares.csv"
    Get-BaselineServiceDeviations | Export-Csv -NoTypeInformation -Append -Path "$Folder\Services.csv"
    Get-BaselineAsepDeviations | Export-Csv -NoTypeInformation -Append -Path "$Folder\StartupPrograms.csv"
    Get-BaselineProgramDeviations | Export-Csv -NoTypeInformation -Append -Path "$Folder\Programs.csv"
}

Get-Credentials
New-SystemSecurityBaselineAudit
