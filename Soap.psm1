function Block-TrafficToIpAddress {
    param([Parameter(Mandatory)][ipaddress]$IpAddress)
    New-NetFirewallRule -DisplayName "Block $IpAddress" -Direction Outbound -Action Block -RemoteAddress $IpAddress
}

function Block-TrafficToRemotePort {
    param([Parameter(Mandatory)][int]$Port)
    New-NetFirewallRule -DisplayName "Block Outbound Port $Port" -Direction Outbound -Protocol TCP -RemotePort $Port -Action Block
}   

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

function ConvertFrom-CsvToMarkdownTable {
    <# .EXAMPLE 
    ConvertFrom-CsvToMarkdownTable -Path .\Report.csv
    #>
    param([Parameter(Mandatory)][string]$Path)
    if (Test-Path -Path $Path) {
        $Csv = Get-Content $Path
        $Headers = $Csv | Select-Object -First 1
        $NumberOfHeaders = ($Headers.ToCharArray() | Where-Object { $_ -eq ',' }).Count + 1
        $MarkdownTable = $Csv | ForEach-Object { '| ' + $_.Replace(',',' | ') + ' |' }
        $MarkdownTable[0] += "`r`n" + ('| --- ' * $NumberOfHeaders) + '|'
        return $MarkdownTable 
    }
}

function Copy-FileToRemotePublicFolder {
	<#
		.SYNOPSIS
		Copies a file to the "Public" folder of one or more remote computers.
	#>
	Param(
		[string]$Computers,
		[string]$File
	)

	$Computers |
	ForEach-Object {
		# for each computer
		$Computer = $_
		# if it is online
		If (Test-Connection -ComputerName $Computer -Count 2 -Quiet) {
			# try and copy the file to the public folder
			Try {
				Copy-Item -Path $File -Destination "\\$_\C`$\Users\Public\"
                Write-Output "Copied $File to $Computer."
			} Catch { 
				"Failed to copy $File to $Computer."
			}
		} Else { 
			Write-Output "$Computer appears to be offline."
		}
	}
}

function Disable-AdStaleAccounts {
    Import-Module ActiveDirectory
    $SearchBase = Read-Host -Prompt 'Distinguished Name (OU Path in LDAP Format) to Scrub'
    # $SearchBase = 'OU=Users,OU=HQ,OU=EvilCorp,DC=sky,DC=net'
    $30_Days_Ago = (Get-Date).AddDays(-30)
    $Filter = { LastLogonDate -le $30_Days_Ago }
    $DomainRoot = $(Get-ADDomain).DistinguishedName
    $DisabledUsersOu = "OU=Disabled Users," + $DomainRoot
    $DisabledUsersOuExists = (Get-ADOrganizationalUnit -Filter *).DistinguishedName -eq $DisabledUsersOu
    if (-not ($DisabledUsersOuExists)) {
        New-ADOrganizationalUnit -Name "Disabled Users" -Path $DomainRoot
    }
    $VipUsers = (Get-ADGroup -Identity 'VIP Users').Sid
    Get-ADUser -Filter $Filter -SearchBase $SearchBase -Properties LastLogonDate,Description | 
    Where-Object { $VipUsers -notcontains $_.Sid } |
    foreach {
        if ($_.Enabled) {
            Set-ADUser $_.SamAccountName -Description $('Last Login - ' + $_.LastLogonDate)
            Disable-ADAccount $_.SamAccountName
        }
        Move-ADObject -Identity $_.DistinguishedName -TargetPath $DisabledUsersOu
    } 
}

function Disable-AdStaleComputers {
    Import-Module ActiveDirectory
    $30_Days_Ago = (Get-Date).AddDays(-30)
    $Filter = { LastLogonDate -le $30_Days_Ago }
    $SearchBase = Read-Host -Prompt 'Distinguished Name (OU Path in LDAP Format)'
    Get-ADComputer -Filter $Filter -Properties LastLogonDate | 
    foreach {
        if ($_.Enabled) {
            Set-ADComputer $_.SamAccountName -Description $('Last Login - ' + $_.LastLogonDate)
            Disable-ADAccount $_.SamAccountName
        }
    } 
    # EXAMPLE OU PATH: OU=Computers,OU=HQ,OU=EvilCorp,DC=vanilla,DC=sky,DC=net
}

function Disable-Firewall {
    Set-NetFirewallProfile -Name domain,public,private -Enabled False
} 

function Disable-Ipv6 {
    Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
}

function Edit-Module {
    Param([Parameter(Mandatory)][string]$Name)
    $Module = Get-Module | Where-Object { $_.Path -like "*$Name.psm1" }
    if ($Module) { 
        ise $Module.Path
    } else {
        Write-Error "A module with the name '$Name' does not exist."
    }
}

function Enable-Firewall {
    Set-NetFirewallProfile -Name domain,public,private -Enabled true
}

function Enable-Ipv6 {
    Enable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
}

function Enable-WinRm {
    param([Parameter(Mandatory)]$ComputerName)
    $Expression = "wmic /node:$ComputerName process call create 'winrm quickconfig'"
    Invoke-Expression $Expression
    #Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c 'winrm qc'"
}

function Export-Gpo {
    Write-Output "`n[+] Available GPOs:"
    $AllGPOs = (Get-GPO -All).DisplayName
    $AllGPOs | ForEach-Object { Write-Output " -   $_"}
    $GPOName = Read-Host -Prompt "`n[+] Which GPO do you want exported? `n -   GPO Name"

    if ($AllGPOs -contains $GPOName) {
        $GPOBackupFolder = "$PWD\" + ($GPOName).Replace(" ", "-") + "GPO"
        $FindingGPOBackupFolder = Test-Path -Path $GPOBackupFolder
        if (-not $FindingGPOBackupFolder) {
            New-Item -Type Directory -Path $GPOBackupFolder | Out-Null
        }
        $GPOGuid = '{' + (Backup-GPO -Name $GPOName -Path $GPOBackupFolder).Id + '}'

        $OldDC = $env:COMPUTERNAME
        $OldNetBIOSName = $env:USERDOMAIN
        $OldDNSDomainName = $env:USERDNSDOMAIN

        $NewDC = 'DC1'
        $NewNetBIOSName = 'CONTOSO'
        $NewDNSDomainName = 'contoso.com'

        $Files = @(
            "$GPOBackupFolder\$GPOGuid\Backup.xml"
            "$GPOBackupFolder\$GPOGuid\bkupInfo.xml" 
            "$GPOBackupFolder\$GPOGuid\gpreport.xml"
        ) 

        $Files |
        ForEach-Object {
            Write-Output "`n[+] Scrubbing $_"
            (Get-Content -Path $_) `
            -replace $OldDC, $NewDC `
            -replace $OldDNSDomainName, $NewDNSDomainName `
            -replace $OldNetBIOSName, $NewNetBIOSName |
            Set-Content $_
            Write-Output " -   Done."
        }
    }
}

function Find-IpAddressInWindowsEventLog {
    param(
        [string]$IpAddress
    )
    $FilterHashTable = @{
        LogName = "Security"
        Id = 5156
    }
    Get-WinEvent -FilterHashtable $FilterHashTable | 
    Read-WinEvent  | 
    Where-Object { 
        ($_.DestAddress -eq $IpAddress) -or 
        ($_.SourceAddress -eq $IpAddress) } | 
    Select-Object TimeCreated, EventRecordId, SourceAddress, DestAddress
}

function Format-Color {
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline)]$Input,
        [Parameter(Mandatory = $true, Position = 1)][string]$Value,
        [Parameter(Mandatory = $true, Position = 2)][string]$BackgroundColor,
        [Parameter(Mandatory = $true, Position = 3)][string]$ForegroundColor
    )
    <#
        .SYNOPSIS
        Hightlights strings of text if they contain a specified value. 
        .PARAMETER Value
        Specifies the value to color if found. 
        .PARAMETER BackgroundColor
        Specifies the background color to use. 
        .PARAMETER ForegroundColor
        Specifies the foreground color to use. 
        .INPUTS
        Format-Color accepts pipeline objects. 
        .OUTPUTS
        Format-Color returns highlighted strings.  
        .EXAMPLE
        Get-ChildItem | Format-Color -Value foo.txt -BackgroundColor Red -ForegroundColor White
        .LINK
        https://www.bgreco.net/powershell/format-color/
        https://www.github.com/cyberphor/scripts/PowerShell/Format-Color.ps1
    #>
    
    $Lines = ($Input | Format-Table -AutoSize | Out-String) -replace "`r", "" -split "`n"
    foreach ($Line in $Lines) {
    	foreach ($Pattern in $Value) { 
            if ($Line -match $Value) { $LineMatchesValue = $true } 
            else { $LineMatchesValue = $false }

            if ($LineMatchesValue) { Write-Host $Line -BackgroundColor $BackgroundColor -ForegroundColor $ForegroundColor } 
            else { Write-Host $Line }
	}
    }
}

function Get-App {
    param([string]$Name)
    $Apps = @()
    $Apps += Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $Apps += Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    return $Apps | Where-Object { $_.DisplayName -like "*$Name*"}
}

function Get-Asset {
    param([switch]$Verbose)
    $NetworkAdapterConfiguration = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = 'True'"
    $IpAddress = $NetworkAdapterConfiguration.IpAddress[0]
    $MacAddress = $NetworkAdapterConfiguration.MACAddress[0]
    $SystemInfo = Get-ComputerInfo
    $Asset = [pscustomobject] @{
        "Hostname" = $env:COMPUTERNAME
        "IpAddress" = $IpAddress
        "MacAddress" = $MacAddress
        "SerialNumber" = $SystemInfo.BiosSeralNumber
        "Make" = $SystemInfo.CsManufacturer
        "Model" = $SystemInfo.CsModel
        "OperatingSystem" = $SystemInfo.OsName
        "Architecture" = $SystemInfo.OsArchitecture
        "Version" = $SystemInfo.OsVersion
    }
    if ($Verbose) { $Asset }
    else { $Asset | Select-Object -Property HostName,IpAddress,MacAddress,SerialNumber}
}

function Get-AuditPolicy {
    Param(
        [ValidateSet("System",`
                     "Logon/Logoff",`
                     "Object Access",`
                     "Privilege Use",`
                     "Detailed Tracking",`
                     "Policy Change",`
                     "Account Management",`
                     "DS Access",`
                     "Account Logon"
        )]$Category
    )
    if ($Category -eq $null) {
        $Category = "System",`
                    "Logon/Logoff",`
                    "Object Access",`
                    "Privilege Use",`
                    "Detailed Tracking",`
                    "Policy Change",`
                    "Account Management",`
                    "DS Access",`
                    "Account Logon"    
    }
    $Category | 
    ForEach-Object {
        $Category = $_
        $Policy = @{}
        ((Invoke-Expression -Command 'auditpol.exe /get /category:"$Category"') `
        -split "`r" -match "\S" | 
        Select-Object -Skip 3).Trim() |
        ForEach-Object {
            $Setting = ($_ -replace "\s{2,}","," -split ",")
            $Policy.Add($Setting[0],$Setting[1])
        }
        $Policy.GetEnumerator() |
        ForEach-Object {
            [PSCustomObject]@{
                Subcategory = $_.Key
                Setting = $_.Value
            }
        }
    }
}

function Get-BaselineConnections {
    Get-NetTcpConnection -State Established | 
    Select-Object -Property `
        OwningProcess,`
        @{ Name = "ProcessName"; Expression = { (Get-Process -Id $_.OwningProcess).ProcessName } },`
        @{ Name = "Path"; Expression = { (Get-Process -Id $_.OwningProcess).Path } },`
        RemoteAddress,`
        RemotePort -Unique | 
    Sort-Object -Property Path,RemotePort |
    Format-Table -AutoSize
}

function Get-BaselinePorts {
    Get-NetTcpConnection -State Listen | 
    Select-Object -Property `
        OwningProcess,`
        @{ Name = "ProcessName"; Expression = { (Get-Process -Id $_.OwningProcess).ProcessName } },`
        @{ Name = "Path"; Expression = { (Get-Process -Id $_.OwningProcess).Path } },`
        LocalPort |
    Sort-Object -Property Path,LocalPort |
    Format-Table -AutoSize
}

function Get-BaselineProcesses {
    Get-Process | 
    Select-Object -Property ProcessName,Path -Unique | 
    Sort-Object -Property Path
}

function Get-Bat {
    <#
        .SYNOPSIS
        Prints an image of a bat using ASCII characters. 

        .LINK
        https://www.asciiart.eu/animals/bats
    #>
    $Bat = "
        =/\                 /\=
        / \'._   (\_/)   _.'/ \
       / .''._'--(o.o)--'_.''. \
      /.' _/ |``'=/ `" \='``| \_ ``.\
     /`` .' ``\;-,'\___/',-;/`` '. '\
    /.-'       ``\(-V-)/``       ``-.\
    ``            `"   `"            ``
    "

    Write-Output $Bat
}

function Get-CallSign {
    $Adjectives = @("Bastard","Brass","Cannibal","Dark","Liquid","Solid","Doom","Gray","Silent","Steel","Stone")
    $Animals = @("Bat","Bear","Bison","Beetle","Cat","Cobra","Fox","Snake","Mantis","Mustang","Tiger")
    $CallSign = $($Adjectives | Get-Random -Count 1) + ' ' + $($Animals | Get-Random -Count 1)
    return $CallSign
}

function Get-DnsEvents {
    Param([string]$Whitelist)
    if ($Whitelist) {
        $Exclusions = Get-Content $Whitelist -ErrorAction Stop
    }
    $FilterHashTable = @{
        LogName = "Microsoft-Windows-DNS-Client/Operational"
        Id = 3006
    }
    Get-WinEvent -FilterHashtable $FilterHashTable |
    Read-WinEvent |
    Where-Object { $_.QueryName -notin $Exclusions } |
    Group-Object -Property QueryName -NoElement |
    Sort-Object -Property Count -Descending |
    Format-Table -AutoSize
}

function Get-ProcessCreationEvents {
    Param([string]$Whitelist)
    if ($Whitelist) {
        $Exclusions = Get-Content $Whitelist -ErrorAction Stop
    }
    $FilterHashTable = @{
        LogName = "Security"
        Id = 4688
    }
    Get-WinEvent -FilterHashtable $FilterHashTable |
    Read-WinEvent |
    Where-Object { $_.NewProcessName -notin $Exclusions } |
    Group-Object -Property NewProcessName -NoElement |
    Sort-Object -Property Count -Descending |
    Format-Table -AutoSize
}

function Get-ProcessCreationReport {
    <#
        .SYNOPSIS
        Searches the Windows "Security" Event log for commands defined in a blacklist and sends an email when a match is found. 
        .DESCRIPTION
        This script will automatically create a file called "SentItems.log" to keep track of what logs have already been emailed (using the Record Id field/value). 
        .INPUTS
        None. You cannot pipe objects to this script.
        .OUTPUTS
        An email.
        .EXAMPLE 
        Get-ProcessCreationReport.ps1 -BlacklistFile ".\command-blacklist.txt" -EmailServer "smtp.gmail.com" -EmailServerPort 587 -EmailAddressSource "DrSpockTheChandelier@gmail.com" -EmailPassword "iHaveABadFeelingAboutThis2022!" -EmailAddressDestination "DrSpockTheChandelier@gmail.com" 
    
        .NOTES
        If you are going to use Gmail, this is what you need to use (as of 17 MAR 22):
        - EmailServer = smtp.gmail.com
        - EmailServerPort = 587
        - EmailAddressSource = YourEmailAddress@gmail.com
        - EmailAddressDestination = AnyEmailAddress@AnyDomain.com
        - EmailPassword = iHaveABadFeelingAboutThis2022!
    
        Also, consider reading this:
        - https://myaccount.google.com/lesssecureapps
    #>

    param(
        [Parameter(Mandatory)][string]$BlacklistFile,
        [Parameter(Mandatory)][string]$EmailServer,
        [Parameter(Mandatory)][int]$EmailServerPort,
        [Parameter(Mandatory)][string]$EmailAddressSource,
        [Parameter(Mandatory)][string]$EmailPassword,
        [Parameter(Mandatory)][string]$EmailAddressDestination,
        [string]$SentItemsLog = ".\SentItems.log"           
    )

    $UserId = [Security.Principal.WindowsIdentity]::GetCurrent()
    $AdminId = [Security.Principal.WindowsBuiltInRole]::Administrator
    $CurrentUser = New-Object Security.Principal.WindowsPrincipal($UserId)
    $RunningAsAdmin = $CurrentUser.IsInRole($AdminId)
    if (-not $RunningAsAdmin) { 
        Write-Error "This script requires administrator privileges."
        break
    }

    # get the command blacklist
    # - commands in your blacklist must include the full-path
    #   - ex: C:\Windows\System32\whoami.exe
    $Blacklist = Get-Content -Path $BlacklistFile

    if (Test-Path $SentItemsLog) {
        # check if the script log exists
        # - save its contents to a variable
        $SentItems = Get-Content -Path $SentItemsLog
    } else {
        # otherwise, create a script log
        # - this is important so you are not sending the same record multiple times
        New-Item -ItemType File -Path $SentItemsLog | Out-Null
    }

    # define the search criteria
    $FilterHashTable = @{
        LogName = "Security"
        Id = 4688
        StartTime = $(Get-Date).AddDays(-1)    
    }

    # cycle through events matching the criteria above
    # - return the first event that contains a command on the blacklist
    $Event = Get-WinEvent -FilterHashtable $FilterHashTable |
        Where-Object { 
            ($Blacklist -contains $_.Properties[5].Value) -and 
            ($SentItems -notcontains $_.RecordId)    
        } | 
        Select-Object * -First 1

    # if there is an event meeting the criteria defined, send an email
    if ($Event) {
        # assign important fields to separate variables for readability
        $EventId = $Event.Id
        $Source = $Event.ProviderName
        $MachineName = $Event.MachineName
        $Message = $Event.Message

        # define values required to send an email via PowerShell
        $EmailClient = New-Object Net.Mail.SmtpClient($EmailServer, $EmailServerPort)
        $Subject = "Alert from $MachineName"
        $Body = "
            EventID: $EventId `r
            Source: $Source `r `
            MachineName: $MachineName `r
            Message: $Message `r
        "
        $EmailClient.EnableSsl = $true
        $EmailClient.Credentials = New-Object System.Net.NetworkCredential($EmailAddressSource, $EmailPassword)
        $EmailClient.Send($EmailAddressSource, $EmailAddressDestination, $Subject, $Body)
        Add-Content -Value $Event.RecordId -Path $SentItemsLog
    }
}

function Get-DiskSpace {
    Get-CimInstance -Class Win32_LogicalDisk |
    Select-Object -Property @{
        Label = 'DriveLetter'
        Expression = { $_.Name }
    },@{
        Label = 'FreeSpace (GB)'
        Expression = { ($_.FreeSpace / 1GB).ToString('F2') }
    },@{
        Label = 'TotalSpace (GB)'
        Expression = { ($_.Size / 1GB).ToString('F2') }
    },@{
        Label = 'SerialNumber'
        Expression = { $_.VolumeSerialNumber }
    }
}

function Get-DomainAdministrators {
    Get-AdGroupMember -Identity "Domain Admins" |
    Select-Object -Property Name,SamAccountName,Sid |
    Format-Table -AutoSize
}

function Get-EnterpriseVisbility {
    param(
        [Parameter(Mandatory)][string]$Network,
        [Parameter(Mandatory)][string]$EventCollector
    )
    $ActiveIps = Get-IpAddressRange -Network $Network | Test-Connections
    $AdObjects = (Get-AdComputer -Filter "*").Name
    $EventForwarders = Get-EventForwarders -ComputerName $EventCollector
    $WinRmclients = Get-WinRmClients
    $Visbility = New-Object -TypeName psobject
    $Visbility | Add-Member -MemberType NoteProperty -Name ActiveIps -Value $ActiveIps.Count
    $Visbility | Add-Member -MemberType NoteProperty -Name AdObjects -Value $AdObjects.Count
    $Visbility | Add-Member -MemberType NoteProperty -Name EventForwarders -Value $EventForwarders.Count
    $Visbility | Add-Member -MemberType NoteProperty -Name WinRmClients -Value $WinRmclients.Count
    return $Visbility
}

function Get-EventFieldNumber {
    param(
        [parameter(Mandatory)][int]$EventId,
        [parameter(Mandatory)][string]$Field
    )
    $LookupTable = "windows-event-fields.json"
    if (Test-Path $LookupTable) {
        $FieldNumber = $(Get-Content $LookupTable | ConvertFrom-Json) |
            Where-Object { $_.Id -eq $EventId } |
            Select-Object -ExpandProperty Fields |
            Select-Object -ExpandProperty $Field -ErrorAction Ignore
        if ($FieldNumber -eq $null) {
            Write-Error "Event ID $EventId does not have a field called $Field."
            break
        } else {
            return $FieldNumber
        }
    } else {
        Write-Error "File not found: $LookupTable"
        break
    }
}

function Get-EventForwarders {
    param(
      [string]$ComputerName,
      [string]$Subscription = "Forwarded Events"
    )
    Invoke-Command -ComputerName $ComputerName -ArgumentList $Subscription -ScriptBlock {
        $Subscription = $args[0]
        $Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\EventCollector\Subscriptions\$Subscription\EventSources"
        $EventForwarders = (Get-ChildItem $Key).Name | ForEach-Object { $_.Split("\")[9] }
        return $EventForwarders
    }
}

function Get-EventViewer {
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
            StartTime = (Get-Date).AddDays(-1)
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
        $Workbook.Worksheets.Item("ProcessCreation").Cells.Item(1,5) = "NewProcessName"
        $Workbook.Worksheets.Item("ProcessCreation").Cells.Item(1,6) = "CommandLine"
    
        # define where to begin adding data (by row and column)
        $rTimeCreated, $cTimeCreated = 2,1
        $rRecordId, $cRecordId = 2,2
        $rUserName, $cUserName = 2,3
        $rParentProcessName, $cParentProcessName = 2,4
        $rNewProcessName, $cNewProcessName = 2,5
        $rCommandLine, $cCommandLine = 2,6

        # define what Windows Event criteria must match 
        $FilterHashTable = @{
            LogName = "Security"
            Id = 4688
            StartTime = (Get-Date).AddDays(-1)

        }
        # cycle through the Windows Events that match the criteria above
        Get-WinEvent -FilterHashtable $FilterHashTable |
        Read-WinEvent |
        Select-Object -Property TimeCreated,EventRecordId,TargetUserName,ParentProcessName,NewProcessName,CommandLine |
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
            $Workbook.Worksheets.Item("ProcessCreation").Cells.Item($rNewProcessName, $cNewProcessName) = $_.NewProcessName
            $Workbook.Worksheets.Item("ProcessCreation").Cells.Item($rCommandLine, $cCommandLine) = $_.CommandLine

            # move-on to the next row
            $rTimeCreated++
            $rRecordId++
            $rUserName++
            $rParentProcessName++
            $rNewProcessName++
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
            StartTime = (Get-Date).AddDays(-1)
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

    $Path = $env:USERPROFILE + "\Desktop\Events-" + $(Get-Date -Format yyyy-MM-dd_hhmm) +".xlsx"
    $Workbook.SaveAs($Path,51)

    Get-SuccessfulLogonEvents
    $Workbook.Worksheets.Item("SuccessfulLogon").UsedRange.Columns.Autofit() | Out-Null

    Get-ProcessCreationEvents
    $Workbook.Worksheets.Item("ProcessCreation").UsedRange.Columns.Autofit() | Out-Null
    $Workbook.Save()

    Get-PowerShellEvents
    $Workbook.Worksheets.Item("PowerShell").UsedRange.Columns.Autofit() | Out-Null
    $Workbook.Save()

    $Excel.Quit()
    Invoke-Item -Path $Path
}

function Get-FirewallEvents {
    Param(
        [ValidateSet("SourceAddress","DestAddress")]$Direction = "DestAddress"
    )

    $FilterHashTable = @{
        LogName = "Security"
        Id = 5156
    }

    Get-WinEvent -FilterHashtable $FilterHashTable |
    Read-WinEvent |
    Group-Object -Property $Direction -NoElement |
    Sort-Object -Property Count -Descending
}


function Get-Indicator {
    param(
        [string]$Path = "C:\Users",
        [Parameter(Mandatory)][string]$FileName
    )
    Get-ChildItem -Path $Path -Recurse -Force -ErrorAction Ignore |
    Where-Object { $_.Name -like $FileName } |
    Select-Object -ExpandProperty FullName
}

function Get-IpAddressRange {
    param([Parameter(Mandatory)][string[]]$Network)
    $IpAddressRange = @()
    $Network |
    foreach {
        if ($_.Contains('/')) {
            $NetworkId = $_.Split('/')[0]
            $SubnetMask = $_.Split('/')[1]
            if ([ipaddress]$NetworkId -and ($SubnetMask -eq 32)) {
                $IpAddressRange += $NetworkId          
            } elseif ([ipaddress]$NetworkId -and ($SubnetMask -le 32)) {
                $Wildcard = 32 - $SubnetMask
                $NetworkIdBinary = ConvertTo-BinaryString $NetworkId
                $NetworkIdIpAddressBinary = $NetworkIdBinary.SubString(0,$SubnetMask) + ('0' * $Wildcard)
                $BroadcastIpAddressBinary = $NetworkIdBinary.SubString(0,$SubnetMask) + ('1' * $Wildcard)
                $NetworkIdIpAddress = ConvertTo-IpAddress $NetworkIdIpAddressBinary
                $BroadcastIpAddress = ConvertTo-IpAddress $BroadcastIpAddressBinary
                $NetworkIdInt32 = [convert]::ToInt32($NetworkIdIpAddressBinary,2)
                $BroadcastIdInt32 = [convert]::ToInt32($BroadcastIpAddressBinary,2)
                $NetworkIdInt32..$BroadcastIdInt32 | 
                foreach {
                    $BinaryString = [convert]::ToString($_,2)
                    $Address = ConvertTo-IpAddress $BinaryString
                    $IpAddressRange += $Address
                }            
            }
        }
    }
    return $IpAddressRange
}

function Get-LocalAdministrators {
    (net localgroup administrators | Out-String).Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries) |
    Select-Object -Skip 4 |
    Select-String -Pattern "The command completed successfully." -NotMatch |
    ForEach-Object {
        New-Object -TypeName PSObject -Property @{ Name = $_ }
    }
}

function Get-LogonEvents {
    Param([ValidateSet("Failed","Successful")]$Type = "Failed")
    if ($Type -eq "Failed") {
        $Id = 4625
    } elseif ($Type -eq "Successful") {
        $Id = 4624
    }
    $FilterHashTable = @{
        LogName = "Security"
        Id = $Id
    }
    Get-WinEvent -FilterHashtable $FilterHashTable |
    Read-WinEvent |
    Group-Object -Property TargetUserName -NoElement |
    Sort-Object -Property Count -Descending
}

function Get-ModuleFunctions {
    param([string]$Module)
    (Get-Module $Module | Select-Object -Property ExportedCommands).ExportedCommands.Keys 
}

function Get-Permissions {
    param(
        [string]$File = $pwd,
        [int]$Depth = 1
    )
    if (Test-Path -Path $File) {
        Get-ChildItem -Path $File -Recurse -Depth $Depth |
        ForEach-Object {
            $Object = New-Object -TypeName PSObject
            $Object | Add-Member -MemberType NoteProperty -Name Name -Value $_.PsChildName
            $Acl = Get-Acl -Path $_.FullName | Select-Object -ExpandProperty Access
            $AclAccount = $Acl.IdentityReference
            $AclRight = ($Acl.FileSystemRights -split ',').Trim()
            for ($Ace = 0; $Ace -lt $AclAccount.Count; $Ace++) {
                $Object | Add-Member -MemberType NoteProperty -Name $AclAccount[$Ace] -Value $AclRight[$Ace]
            }
            return $Object
        }
    }
}

function Get-Privileges {
    # powershell.exe "whoami /priv | findstr Enabled | % { $_.Split(" ")[0] } > C:\Users\Public\privileges-$env:USERNAME.txt"
    # create a scheduled task and run this command...using the Users group

    SecEdit.exe /export /areas USER_RIGHTS /cfg ./user-rights.txt /quiet
    $Privileges = Get-Content .\user-rights.txt | Where-Object { $_.StartsWith("Se") }
    Remove-Item .\user-rights.txt | Out-Null

    $Privileges |
    ForEach-Object {
        $Assignment = $_.Split(" = ")
        $Privilege = $Assignment[0]
        $Sids = $Assignment[3].Split(",") |
            ForEach-Object {
                if ($_.StartsWith("*")) {
                    $_.Substring(1)
                } else {
                    $_
                }
            }
        $Sids | 
        ForEach-Object {
            $Sid = $_
            $UserAccount = Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Sid -eq $Sid } | Select-Object -ExpandProperty Name
            $BuiltInAccount = Get-WmiObject -Class Win32_Account | Where-Object { $_.Sid -eq $Sid } | Select-Object -ExpandProperty Name
            $BuiltInGroup = Get-WmiObject -Class Win32_Group | Where-Object { $_.Sid -eq $Sid } | Select-Object -ExpandProperty Name

            if ($UserAccount) {
                $Username = $UserAccount
            } elseif ($BuiltInAccount) {
                $Username = $BuiltInAccount
            } elseif ($BuiltInGroup) {
                $Username = $BuiltInGroup
            } else {
                $Username = $Sid
            }
        
            $Output = New-Object psobject
            Add-Member -InputObject $Output -MemberType NoteProperty -Name Privilege -Value $Privilege
            Add-Member -InputObject $Output -MemberType NoteProperty -Name Sid -Value $_
            Add-Member -InputObject $Output -MemberType NoteProperty -Name Username -Value $Username
            $Output
        }
    }
}

function Get-ProcessToKill {
    param([Parameter(Mandatory)]$Name)
    $Process = Get-Process | Where-Object { $_.Name -like $Name }
    $Process.Kill()
}

function Get-SerialNumberAndCurrentUser {
    Param([string[]]$ComputerName)
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        Get-WmiObject -Class Win32_Bios | Select-Object -ExpandProperty SerialNumber
        Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName
    }
}

function Get-Shares {
    param([string[]]$Whitelist = @("ADMIN$","C$","IPC$"))
    Get-SmbShare | 
    Where-Object { $Whitelist -notcontains $_.Name } |
    Select-Object -Property Name, Path, Description
}

function Get-Stig {
    <#
        .SYNOPSIS
        Returns STIG rules as PowerShell objects.
                
        .DESCRIPTION
        Returns Security Technical Implementation Guide (STIG) rules as PowerShell objects after reading an Extensible Configuration Checklist Description Format (XCCDF) document.

        .INPUTS
        None. You cannot pipe objects to Get-Stig.

        .OUTPUTS
        PSCustomObject.

        .EXAMPLE
        Get-Stig -Path 'U_MS_Windows_10_STIG_V2R3_Manual-xccdf.xml'

        .LINK
        https://gist.github.com/entelechyIT
    #>
    Param([Parameter(Mandatory)]$Path)
    if (Test-Path $Path) {
        [xml]$XCCDFdocument = Get-Content -Path $Path
        if ($XCCDFdocument.Benchmark.xmlns -like 'http://checklists.nist.gov/xccdf/*') {
            $Stig = @()
            $XCCDFdocument.Benchmark.Group.Rule |
            ForEach-Object {
                $Rule = New-Object -TypeName PSObject -Property ([ordered]@{
                    RuleID    = $PSItem. id
                    RuleTitle = $PSItem.title 
                    Severity = $PSItem.severity
                    VulnerabilityDetails = $($($($PSItem.description) -split '</VulnDiscussion>')[0] -replace '<VulnDiscussion>', '')
                    Check = $PSItem.check.'check-content'
                    Fix = $PSItem.fixtext.'#text'
                    ControlIdentifier = $PSItem.ident.'#text'
                    Control = $null 
                })
                $Stig += $Rule
            }
            return $Stig
        } 
        Write-Error 'The file provided is not a XCCDF document.'
    }
}

function Get-TcpPort {
    Get-NetTCPConnection | 
    Select-Object @{ "Name" = "ProcessId"; "Expression" = { $_.OwningProcess }},LocalPort,@{ "Name" = "ProcessName"; "Expression" = { (Get-Process -Id $_.OwningProcess).Name }},RemoteAddress |
    Sort-Object -Property ProcessId -Descending
}

function Get-UsbEvents {
    $FilterHashTable = @{
        LogName = "Security"
        Id = 6416
    }

    Get-WinEvent -FilterHashtable $FilterHashTable |
    Read-WinEvent |
    Group-Object -Property DeviceDescription -NoElement |
    Sort-Object -Property Count -Descending |
    Format-Table -AutoSize
}

function Get-WhoIs {
    $FilterHashTable = @{
        LogName = 'Microsoft-Windows-Sysmon/Operational' 
        Id = 3
    }
    Get-WinEvent -FilterHashtable $FilterHashTable |
    Read-WinEvent |
    Select-Object SourceIp,DestinationIp,DestinationPort | 
    Sort-Object -Property DestinationIp -Unique | 
    ForEach-Object {
        $Header = @{"Accept" = "application/xml"}
        $Response = Invoke-Restmethod -Uri $("http://whois.arin.net/rest/ip/" + $_.DestinationIp) -Headers $Header -ErrorAction Ignore
        $Organization = $Response.net.orgRef.name
        if ($Organization -ne 'Microsoft Corporation') {
            return New-Object -TypeName psobject -Property @{SourceIp = $_.SourceIp; DestinationIp = $_.DestinationIp; DestinationPort = $_.DestinationPort; Organization = $Organization}
        } 
    }
}

function Get-WinRmClients {
    $ComputerNames = $(Get-AdComputer -Filter *).Name
    Invoke-Command -ComputerName $ComputerNames -ScriptBlock { $env:HOSTNAME } -ErrorAction Ignore
}

function Get-WirelessNetAdapter {
    param([string]$ComputerName = $env:COMPUTERNAME)
    Get-WmiObject -ComputerName $ComputerName -Class Win32_NetworkAdapter |
    Where-Object { $_.Name -match 'wi-fi|wireless' }
}

function Get-WordWheelQuery {
    $Key = "Registry::HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"
    Get-Item $Key | 
    Select-Object -Expand Property | 
    ForEach-Object {
        if ($_ -ne "MRUListEx") {
            $Value = (Get-ItemProperty -Path $Key -Name $_).$_
            [System.Text.Encoding]::Unicode.GetString($Value)
        }
    }
}

function Import-CustomViews {
    param([string]$Path = "C:\Program Files\WindowsPowerShell\Modules\SOAP-Modules\Custom-Views")
    $CustomViewsFolder = "C:\ProgramData\Microsoft\Event Viewer\Views"
    $CustomViews = Get-ChildItem -Recurse $CustomViewsFolder
    Get-ChildItem -Recurse "$Path\*.xml" |
    Where-Object { $_.Name -notin $CustomViews } | 
    Copy-Item -Destination $CustomViewsFolder
}

function Invoke-WinEventParser {
    param(
        [Parameter(Position=0)][string]$ComputerName,
        [ValidateSet("Application","Security","System","ForwardedEvents","Microsoft-Windows-PowerShell/Operational")][Parameter(Position=1)][string]$LogName,
        [ValidateSet("4104","4624","4625","4663","4672","4688","4697","5140","5156","6416")][Parameter(Position=2)]$EventId,
        [Parameter(Position=3)][int]$DaysAgo=1,
        [Parameter(Position=4)][switch]$TurnOffOutputFilter
    )
    if ($TurnOffOutputFilter) {
        Get-WinEvent -FilterHashtable @{ LogName=$LogName; Id=$EventId } |
        Read-WinEvent
    } else {
        if ($EventId -eq "4104") { $Properties = "TimeCreated","SecurityUserId","ScriptBlockText" }
        elseif ($EventId -eq "4624") { $Properties = "TimeCreated","IpAddress","TargetUserName","LogonType" }
        elseif ($EventId -eq "4625") { $Properties = "TimeCreated","IpAddress","TargetUserName","LogonType" }
        elseif ($EventId -eq "4663") { $Properties = "*" }
        elseif ($EventId -eq "4672") { $Properties = "TimeCreated","SubjectUserSid","SubjectUserName" }
        elseif ($EventId -eq "4688") { $Properties = "TimeCreated","TargetUserName","NewProcessName","CommandLine" }
        elseif ($EventId -eq "4697") { $Properties = "*" }
        elseif ($EventId -eq "5140") { $Properties = "*" }
        elseif ($EventId -eq "5156") { $Properties = "TimeCreated","SourceAddress","DestAddress","DestPort" }
        elseif ($EventId -eq "6416") { $Properties = "TimeCreated","SubjectUserName","ClassName","DeviceDescription" }
        else { $Properties = "*" }
        Get-WinEvent -FilterHashtable @{ LogName=$LogName; Id=$EventId } |
        Read-WinEvent |
        Select-Object -Property $Properties
    }
}

function New-CustomViewsForSysmon {
    $SysmonFolder = "C:\ProgramData\Microsoft\Event Viewer\Views\Sysmon"
    if (-not (Test-Path -Path $SysmonFolder)) {
        New-Item -ItemType Directory -Path $SysmonFolder
    }
    $Events = @{
        "1" = "Process-Creation"
        "2" = "A-Process-Changed-A-File-Creation-Time"
        "3" = "Network-Connection"
        "4" = "Sysmon-Service-State-Changed"
        "5" = "Process-Terminated"
        "6" = "Driver-Loaded"
        "7" = "Image-Loaded"
        "8" = "Create-Remote-Thread"
        "9" = "Raw-Access-Read"
        "10" = "Process-Access"
        "11" = "File-Create"
        "12" = "Registry-Event-Object-Create-Delete"
        "13" = "Registry-Event-Value-Set"
        "14" = "Registry-Event-Key-and-Value-Rename"
        "15" = "File-Create-Stream-Hash"
        "16" = "Service-Configuration-Change"
        "17" = "Pipe-Event-Pipe-Created"
        "18" = "Pipe-Event-Pipe-Connected"
        "19" = "Wmi-Event-WmiEventFilter-Activity-Detected"
        "20" = "Wmi-Event-WmiEventConsumer-Activity-Detected"
        "21" = "Wmi-Event-WmiEventConsumerToFilter-Activity-Detected"
        "22" = "DNS-Event"
        "23" = "File-Delete-Archived"
        "24" = "Clipboard-Change"
        "25" = "Process-Tampering"
        "26" = "File-Delete-Logged"
        "255" = "Error"
    }
    $Events.GetEnumerator() | 
    ForEach-Object {
        $CustomViewFilePath = "$SysmonFolder\Sysmon-EventId-" + $_.Name + ".xml"
        if (-not (Test-Path -Path $CustomViewFilePath)) {
            $CustomViewConfig = '<ViewerConfig><QueryConfig><QueryParams><Simple><Channel>Microsoft-Windows-Sysmon/Operational</Channel><EventId>' + $_.Key + '</EventId><RelativeTimeInfo>0</RelativeTimeInfo><BySource>False</BySource></Simple></QueryParams><QueryNode><Name>' + $_.Value + '</Name><QueryList><Query Id="0" Path="Microsoft-Windows-Sysmon/Operational"><Select Path="Microsoft-Windows-Sysmon/Operational">*[System[(EventID=' + $_.Key + ')]]</Select></Query></QueryList></QueryNode></QueryConfig><ResultsConfig><Columns><Column Name="Level" Type="System.String" Path="Event/System/Level" Visible="">217</Column><Column Name="Keywords" Type="System.String" Path="Event/System/Keywords">70</Column><Column Name="Date and Time" Type="System.DateTime" Path="Event/System/TimeCreated/@SystemTime" Visible="">267</Column><Column Name="Source" Type="System.String" Path="Event/System/Provider/@Name" Visible="">177</Column><Column Name="Event ID" Type="System.UInt32" Path="Event/System/EventID" Visible="">177</Column><Column Name="Task Category" Type="System.String" Path="Event/System/Task" Visible="">181</Column><Column Name="User" Type="System.String" Path="Event/System/Security/@UserID">50</Column><Column Name="Operational Code" Type="System.String" Path="Event/System/Opcode">110</Column><Column Name="Log" Type="System.String" Path="Event/System/Channel">80</Column><Column Name="Computer" Type="System.String" Path="Event/System/Computer">170</Column><Column Name="Process ID" Type="System.UInt32" Path="Event/System/Execution/@ProcessID">70</Column><Column Name="Thread ID" Type="System.UInt32" Path="Event/System/Execution/@ThreadID">70</Column><Column Name="Processor ID" Type="System.UInt32" Path="Event/System/Execution/@ProcessorID">90</Column><Column Name="Session ID" Type="System.UInt32" Path="Event/System/Execution/@SessionID">70</Column><Column Name="Kernel Time" Type="System.UInt32" Path="Event/System/Execution/@KernelTime">80</Column><Column Name="User Time" Type="System.UInt32" Path="Event/System/Execution/@UserTime">70</Column><Column Name="Processor Time" Type="System.UInt32" Path="Event/System/Execution/@ProcessorTime">100</Column><Column Name="Correlation Id" Type="System.Guid" Path="Event/System/Correlation/@ActivityID">85</Column><Column Name="Relative Correlation Id" Type="System.Guid" Path="Event/System/Correlation/@RelatedActivityID">140</Column><Column Name="Event Source Name" Type="System.String" Path="Event/System/Provider/@EventSourceName">140</Column></Columns></ResultsConfig></ViewerConfig>'
            Add-Content -Path $CustomViewFilePath -Value $CustomViewConfig
        } 
    }
}

function New-CustomViewsForTheSexySixEventIds {
    <#
        .SYNOPSIS
        Creates custom views for the following Event IDs: 4688, 4624, 5140, 5156, 4697, and 4663.

        .DESCRIPTION
        Open "Event Viewer" to see and use the custom views built by this function.

        .INPUTS
        None.

        .OUTPUTS
        Six custom views in the "C:\ProgramData\Microsoft\Event Viewer\Views" directory.

        .LINK
        https://www.slideshare.net/Hackerhurricane/finding-attacks-with-these-6-events
    #>

    # define where the custom views will be housed
    $Directory = "C:\ProgramData\Microsoft\Event Viewer\Views\Sexy-Six-Event-IDs"

    # create the custom views directory if not already done
    if (-not (Test-Path -Path $Directory)) {
        New-Item -ItemType Directory -Path $Directory | Out-Null
    }

    # create a hashtable for event IDs and their names
    $Events = @{
        "4688" = "Process-Creation"
        "4624" = "Successful-Logons"
        "5140" = "Shares-Accessed"
        "5156" = "Network-Connections"
        "4697" = "New-Services"
        "4663" = "File-Access"
    }

    # for every event
    $Events.GetEnumerator() | 
    ForEach-Object {
        # define the filepath to the custom view
        $FilePath = "$Directory\" + $_.Value + ".xml"

        # if the filepath does not exist
        if (-not (Test-Path -Path $FilePath)) {
            # define the custom view's variables
            $ChannelPath = "Security"
            $EventId = $_.Key
            $ViewName = $_.Value

            # define the custom view using the variables above
            $CustomView = @"
                <ViewerConfig>
                    <QueryConfig>
                        <QueryParams>
                            <Simple>
                                <Channel>$ChannelPath</Channel>
                                <EventId>$EventId</EventId>
                                <RelativeTimeInfo>0</RelativeTimeInfo>
                                <BySource>False</BySource>
                            </Simple>
                        </QueryParams>
                        <QueryNode>
                            <Name>$ViewName</Name>
                            <QueryList>
                                <Query Id="0" Path="$ChannelPath">
                                    <Select Path="$ChannelPath">
                                    *[System[(EventID=$EventId)]]
                                    </Select>
                                </Query>
                            </QueryList>
                        </QueryNode>
                    </QueryConfig>
                    <ResultsConfig>
                        <Columns>
                            <Column Name="Level" Type="System.String" Path="Event/System/Level" Visible="">217</Column>
                            <Column Name="Keywords" Type="System.String" Path="Event/System/Keywords">70</Column>
                            <Column Name="Date and Time" Type="System.DateTime" Path="Event/System/TimeCreated/@SystemTime" Visible="">267</Column>
                            <Column Name="Source" Type="System.String" Path="Event/System/Provider/@Name" Visible="">177</Column>
                            <Column Name="Event ID" Type="System.UInt32" Path="Event/System/EventID" Visible="">177</Column>
                            <Column Name="Task Category" Type="System.String" Path="Event/System/Task" Visible="">181</Column>
                            <Column Name="User" Type="System.String" Path="Event/System/Security/@UserID">50</Column>
                            <Column Name="Operational Code" Type="System.String" Path="Event/System/Opcode">110</Column>
                            <Column Name="Log" Type="System.String" Path="Event/System/Channel">80</Column>
                            <Column Name="Computer" Type="System.String" Path="Event/System/Computer">170</Column>
                            <Column Name="Process ID" Type="System.UInt32" Path="Event/System/Execution/@ProcessID">70</Column>
                            <Column Name="Thread ID" Type="System.UInt32" Path="Event/System/Execution/@ThreadID">70</Column>
                            <Column Name="Processor ID" Type="System.UInt32" Path="Event/System/Execution/@ProcessorID">90</Column>
                            <Column Name="Session ID" Type="System.UInt32" Path="Event/System/Execution/@SessionID">70</Column>
                            <Column Name="Kernel Time" Type="System.UInt32" Path="Event/System/Execution/@KernelTime">80</Column>
                            <Column Name="User Time" Type="System.UInt32" Path="Event/System/Execution/@UserTime">70</Column>
                            <Column Name="Processor Time" Type="System.UInt32" Path="Event/System/Execution/@ProcessorTime">100</Column>
                            <Column Name="Correlation Id" Type="System.Guid" Path="Event/System/Correlation/@ActivityID">85</Column>
                            <Column Name="Relative Correlation Id" Type="System.Guid" Path="Event/System/Correlation/@RelatedActivityID">140</Column>
                            <Column Name="Event Source Name" Type="System.String" Path="Event/System/Provider/@EventSourceName">140</Column>
                        </Columns>
                    </ResultsConfig>
                </ViewerConfig>
"@
            # add the custom view data to the filepath (creating it at the same time)
            Add-Content -Value $CustomView -Path $FilePath
        }
    }
}

function New-PowerShellModule {
    param(
        [Parameter(Mandatory,Position=0)][string]$Name,
        [Parameter(Mandatory,Position=1)][string]$Author,
        [Parameter(Mandatory,Position=2)][string]$Description
    )
    $Directory = "C:\Program Files\WindowsPowerShell\Modules\$Name"
    $Module = "$Directory\$Name.psm1"
    $Manifest = "$Directory\$Name.psd1"
    if (Test-Path -Path $Directory) {
        Write-Output "[x] The $Name module already exists."
    } else { 
        New-Item -ItemType Directory -Path $Directory | Out-Null
        New-Item -ItemType File -Path $Module | Out-Null
        New-ModuleManifest -Path $Manifest `
            -Author $Author `
            -RootModule "$Name.psm1" `
            -Description $Description
        if (Test-Path -Path $Module) {
            Write-Output "[+] Created the $Name module."
        }
    }
}

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

function Remove-App {
    param([Parameter(Mandatory,ValueFromPipelineByPropertyName)][string]$UninstallString)
    if ($UninstallString -contains "msiexec") {
        $App = ($UninstallString -Replace "msiexec.exe","" -Replace "/I","" -Replace "/X","").Trim()
        Start-Process "msiexec.exe" -ArgumentList "/X $App /qb" -NoNewWindow
    } else {
        Start-Process $UninstallString -NoNewWindow
    }
}

function Remove-StaleDnsRecords {
    <#
        .LINK
        https://adamtheautomator.com/powershell-dns/
    #>
    Import-Module DnsServer
    $Domain = Read-Host -Prompt 'Domain Name'
    $30_Days_Ago = (Get-Date).AddDays(-30)
    Get-DnsServerResourceRecord -Zone $Domain -RRType A | 
    Where-Object { $_.TimeStamp -le $30_Days_Ago } | 
    Remove-DnsServerResourceRecord -ZoneName $Domain -Force
}

function Send-Alert {
    [CmdletBinding(DefaultParameterSetName = 'Log')]
    Param(
        [Parameter(Mandatory, Position = 0)][ValidateSet("Balloon","Log","Email")][string]$AlertMethod,
        [Parameter(Mandatory, Position = 1)]$Subject,
        [Parameter(Mandatory, Position = 2)]$Body,
        [Parameter(ParameterSetName = "Log")][string]$LogName,
        [Parameter(ParameterSetName = "Log")][string]$LogSource,
        [Parameter(ParameterSetName = "Log")][ValidateSet("Information","Warning")]$LogEntryType = "Warning",
        [Parameter(ParameterSetName = "Log")][int]$LogEventId = 1,
        [Parameter(ParameterSetName = "Email")][string]$EmailServer,
        [Parameter(ParameterSetName = "Email")][string]$EmailServerPort,
        [Parameter(ParameterSetName = "Email")][string]$EmailAddressSource,
        [Parameter(ParameterSetName = "Email")][string]$EmailPassword,
        [Parameter(ParameterSetName = "Email")][string]$EmailAddressDestination
    )
    <#
        .SYNOPSIS
        Sends an alert. 

        .DESCRIPTION
        When called, this function will either write to the Windows Event log, send an email, or generate a Windows balloon tip notification.
        
        .LINK
        https://mcpmag.com/articles/2017/09/07/creating-a-balloon-tip-notification-using-powershell.aspx
    #>

    if ($AlertMethod -eq "Balloon") {
        Add-Type -AssemblyName System.Windows.Forms
        Unregister-Event -SourceIdentifier IconClicked -ErrorAction Ignore
        Remove-Job -Name IconClicked -ErrorAction Ignore
        Remove-Variable -Name Balloon -ErrorAction Ignore
        $Balloon = New-Object System.Windows.Forms.NotifyIcon
        [void](Register-ObjectEvent `
            -InputObject $Balloon `
            -EventName MouseDoubleClick `
            -SourceIdentifier IconClicked `
            -Action { $Balloon.Dispose() }
        )
        $IconPath = (Get-Process -Id $pid).Path
        $Balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($IconPath)
        $Balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
        $Balloon.BalloonTipTitle = $Subject
        $Balloon.BalloonTipText = $Body
        $Balloon.Visible = $true
        $Balloon.ShowBalloonTip(10000)
    } elseif ($AlertMethod -eq "Log") {
        $LogExists = Get-EventLog -LogName $LogName -Source $LogSource -ErrorAction Ignore -Newest 1
        if (-not $LogExists) {
            New-EventLog -LogName $LogName -Source $LogSource -ErrorAction Ignore
        }
        Write-EventLog `
            -LogName $LogName `
            -Source $LogSource `
            -EntryType $LogEntryType `
            -EventId $LogEventId `
            -Message $Body
    } elseif ($AlertMethod -eq "Email") {
        $EmailClient = New-Object Net.Mail.SmtpClient($EmailServer, $EmailServerPort)
        $EmailClient.EnableSsl = $true
        $EmailClient.Credentials = New-Object System.Net.NetworkCredential($EmailAddressSource, $EmailPassword)
        $EmailClient.Send($EmailAddressSource, $EmailAddressDestination, $Subject, $Body)
    }
}

function Start-AdScrub {
    Import-Module ActiveDirectory

    $30DaysAgo = (Get-Date).AddDays(-30)
    $AtctsReport = Import-Csv $Report | Select Name, @{Name='TrainingDate';Expression={$_.'Date Awareness Training Completed'}}
    $AdSearchBase = ''
    $DisabledUsersOu = '' + $AdSearchBase
    $AdUserAccounts = Get-AdUser -Filter * -SearchBase $AdSearchBase -Properties LastLogonDate
    $VipUsers = $(Get-AdGroup -Identity 'VIP Users').Sid
    $UsersInAtctsReport = $AtctsReport.Name.ToUpper() |
    foreach {
        $SpaceBetweenFirstAndMiddle = $_.Substring($_.Length -2).Substring(0,1)
        if ($SpaceBetweenFirstAndMiddle) { $_ -replace ".$" }
    }

    $AdUserAccounts |
    Where-Object { $VipUsers -notcontains $_.Sid } |
    foreach {
        $NotCompliant = $false
        $Reason = 'Disabled:'

        if ($_.Surname -and $_.GivenName) {
            $FullName = ($_.Surname + ', ' + $_.GivenName).ToUpper()
        } else {
            $FullName = ($_.SamAccountName).ToUpper()
        }

        $AtctsProfile = $UsersInAtctsReport | Where-Object { $_ -like "$FullName*" }

        if (-not $AtctsProfile) {
            $NotCompliant = $true
            $Reason = $Reason + ' ATCTS profile does not exist.'
        }

        if ($AtctsProfile) {
            $TrainingDate = ($AtctsReport | Where-Object { $_.Name -like "$FullName*" }).TrainingDate
            $NewDate = $TrainingDate.Split('-')[0]+ $TrainingDate.Split('-')[2] + $TrainingDate.Split('-')[1]
            $ExpirationDate = (Get-Date $NewDate).AddYears(1).ToString('yyyy-MM-dd')
            if ($ExpirationDate -lt $(Get-Date -Format 'yyyy-MM-dd')){
                $NotCompliant = $true
                $Reason = $Reason + ' Training has expired.'
            }
        }

        if ($_.LastLogonDate -le $30DaysAgo) {
            $NotCompliant = $true
            $Reason = $Reason + 'Inactive for 30 days.'
        }

        if ($NotCompliant) {
            Set-AdUser $_.SamAccountName -Description $Reason
            Disable-AdAccount $_.SamAccountName
            Move-AdObject -Identity $_.DistinguishedName -TargetPath $DisabledUsersOu
            Write-Output "[+] $($_.Name) - $Reason"
        }
    }
}

function Start-Heartbeat {
    Param([string]$Target)
    while (-not $TimeToStop) {
        if (Test-Connection -ComputerName $Target -Count 2 -Quiet) {
            $Timestamp = (Get-Date).ToString('yyyy-MM-dd hh:mm:ss')
            Write-Host "[$Timestamp] [$Target] " -NoNewline
            Write-Host " ONLINE  " -BackgroundColor Green -ForegroundColor Black
        } else {
            $Timestamp = (Get-Date).ToString('yyyy-MM-dd hh:mm:ss')
            Write-Host "[$Timestamp] [$Target] " -NoNewline
            Write-Host " OFFLINE " -BackgroundColor Red -ForegroundColor Black
        }
        Start-Sleep -Seconds 60
        $TimeToStop = (Get-Date).ToString('hh:mm') -le (Get-Date '17:00').ToString('hh:mm')
    }

    $Timestamp = (Get-Date).ToString('yyyy-MM-dd hh:mm:ss')
    Write-Host "[$Timestamp] Time has expired."
}

function Import-AdUsersFromCsv {
    $Password = ConvertTo-SecureString -String '1qaz2wsx!QAZ@WSX' -AsPlainText -Force
    Import-Csv -Path .\users.csv |
    ForEach-Object {
        $Name = $_.LastName + ', ' + $_.FirstName
        $SamAccountName = ($_.FirstName + '.' + $_.LastName).ToLower()
        $UserPrincipalName = $SamAccountName + '@evilcorp.local'
        $Description = $_.Description
        $ExpirationDate = Get-Date -Date 'October 31 2022'
        New-AdUser `
            -Name $Name `
            -DisplayName $Name `
            -GivenName $_.FirstName `
            -Surname $_.LastName `
            -SamAccountName $SamAccountName `
            -UserPrincipalName $UserPrincipalName `
            -Description $Description `
            -ChangePasswordAtLogon $true `
            -AccountExpirationDate $ExpirationDate `
            -Enabled $true `
            -Path 'OU=Users,OU=evilcorp,DC=local' `
            -AccountPassword $Password
    }
}

function Set-AuditPolicy {
    <#
        .SYNOPSIS
        Configures the local audit policy. 

        .DESCRIPTION
        Configures the local audit policy using recommendations from Microsoft, DISA, or Malware Archaeology.

        .INPUTS
        None.

        .OUTPUTS
        None.

        .EXAMPLE
        Set-AuditPolicy.ps1 -Source "Malware Archaeology"

        .LINK
        https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations 
        https://www.malwarearchaeology.com/s/Windows-Logging-Cheat-Sheet_ver_Feb_2019.pdf
        https://cryptome.org/2014/01/nsa-windows-event.pdf
        https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/ 
    #>

    Param(
        [ValidateSet('Microsoft','DISA','Malware Archaeology')]$Source,
        [switch]$EnableDnsLogging,
        [switch]$DisableDnsLogging
    )

    function Set-AuditPolicyUsingMicrosoftRecommendations {
        auditpol /clear /y

        # Account Logon
        # - Event IDs: 4774, 4776
        auditpol /set /subcategory:"Credential Validation" /success:enable

        # Account Management
        # - Event IDs: 4741, 4742, 4743
        auditpol /set /subcategory:"Computer Account Management" /success:enable

        # - Event IDs: 4739, 4782, 4793
        auditpol /set /subcategory:"Other Account Management Events" /success:enable

        # - Event IDs: 4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737, 4754, 4755, 4756, 4757, 4758, 4764, 4799
        auditpol /set /subcategory:"Security Group Management" /success:enable

        # - Event IDs: 4738, 4740, 4765, 4767, 4780, 4781, 
        auditpol /set /subcategory:"User Account Management" /success:enable

        # Detailed Tracking
        # - Event ID: 4688
        auditpol /set /subcategory:"Process Creation" /success:enable

        # Logon/Logoff
        # - Event IDs: 4624, 4625
        auditpol /set /subcategory:"Logon" /success:enable /failure:enable

        # - Event IDs: 4634, 4647
        auditpol /set /subcategory:"Logoff" /success:enable

        # - Event IDs: 4672, 4964
        auditpol /set /subcategory:"Special Logon" /success:enable

        # Policy Change
        # - Event IDs: 4715, 4719, 4817, 4902, 4904, 4905, 4906, 4907, 4908, 4912
        auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable

        # - Event IDs: 4706, 4707, 4713, 4716, 4717, 4718, 4865, 4866, 4867
        auditpol /set /subcategory:"Authentication Policy Change" /success:enable

        # System
        # - Event IDs: 5478, 5479, 5480, 5483, 5484, 5485
        auditpol /set /subcategory:"IPSec Driver" /success:enable /failure:enable

        # - Event IDs: 4608, 4609, 4616, 4621
        auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable

        # - Event IDs: 4610, 4611, 4614, 4622, 4697
        auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable

        # - Event IDs: 4612, 4615, 4618, 5038, 5056, 5061, 5890, 6281, 6410
        auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
    }

    function Set-AuditPolicyUsingMalwareArchaeologyRecommendations {
        # DNS 
        wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:true

        # DHCP
        wevtutil sl "Microsoft-Windows-Dhcp-Client/Operational" /e:true

        auditpol /clear /y

        # Account Logon
        auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

        auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable

        # Account Management
        auditpol /set /category:"Account Management" /success:enable /failure:enable

        # Detailed Tracking
        auditpol /set /subcategory:"Plug and Play Events" /success:enable

        auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

        auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable

        auditpol /set /subcategory:"Token Right Adjusted Events" /success:enable

        # Logon/Logoff
        auditpol /set /subcategory:"Account Lockout" /success:enable

        auditpol /set /subcategory:"Group Membership" /success:enable

        auditpol /set /subcategory:"Logon" /success:enable

        auditpol /set /subcategory:"Logoff" /success:enable

        auditpol /set /subcategory:"Network Policy Server" /success:enable

        auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable

        auditpol /set /subcategory:"Special Logon" /success:enable

        # Object Access
        auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable

        auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable

        auditpol /set /subcategory:"Detailed File Share" /success:enable

        auditpol /set /subcategory:"File Share" /success:enable /failure:enable

        auditpol /set /subcategory:"File System" /success:enable

        auditpol /set /subcategory:"Filtering Platform Connection" /success:enable

        auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable

        auditpol /set /subcategory:"Registry" /success:enable

        auditpol /set /subcategory:"SAM" /success:enable

        # Policy Change
        auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable

        auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable

        auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable

        auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable 

        # Privilege Use
        auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

        # System
        auditpol /set /subcategory:"IPsec Driver" /success:enable

        auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable

        auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable

        auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable

        # Process Command Line
        reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
    }

    function Set-AuditPolicyUsingTheDisaStigForWindows10 {
        auditpol /clear /y

        # V-220748
        auditpol /set /subcategory:"Credential Validation" /failure:enable

        # V-220749
        auditpol /set /subcategory:"Credential Validation" /success:enable

        # V-220750
        auditpol /set /subcategory:"Security Group Management" /success:enable

        # V-220751
        auditpol /set /subcategory:"User Account Management" /failure:enable

        # V-220752
        auditpol /set /subcategory:"User Account Management" /success:enable

        # V-220753
        auditpol /set /subcategory:"Plug and Play Events" /success:enable

        # V-220754
        auditpol /set /subcategory:"Process Creation" /success:enable

        # V-220755
        auditpol /set /subcategory:"Account Lockout" /failure:enable

        # V-220756
        auditpol /set /subcategory:"Group Membership" /success:enable

        # V-220757
        auditpol /set /subcategory:"Logoff" /success:enable

        # V-220758
        auditpol /set /subcategory:"Logon" /failure:enable

        # V-220759
        auditpol /set /subcategory:"Logon" /success:enable

        # V-220760
        auditpol /set /subcategory:"Special Logon" /success:enable

        # V-220761
        auditpol /set /subcategory:"File Share" /failure:enable

        # V-220762
        auditpol /set /subcategory:"File Share" /success:enable

        # V-220763
        auditpol /set /subcategory:"Other Object Access Events" /success:enable

        # V-220764
        auditpol /set /subcategory:"Other Object Access Events" /failure:enable

        # V-220765
        auditpol /set /subcategory:"Removable Storage" /failure:enable

        # V-220766
        auditpol /set /subcategory:"Removable Storage" /success:enable

        # V-220767
        auditpol /set /subcategory:"Audit Policy Change" /success:enable

        # V-220768
        auditpol /set /subcategory:"Authentication Policy Change" /success:enable

        # V-220769
        auditpol /set /subcategory:"Authorization Policy Change" /success:enable

        # V-220770
        auditpol /set /subcategory:"Sensitive Privilege Use" /failure:enable

        # V-220771
        auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable

        # V-220772
        auditpol /set /subcategory:"IPSec Driver" /failure:enable

        # V-220773
        auditpol /set /subcategory:"Other System Events" /success:enable

        # V-220774
        auditpol /set /subcategory:"Other System Events" /failure:enable

        # V-220775
        auditpol /set /subcategory:"Security State Change" /success:enable

        # V-220776
        auditpol /set /subcategory:"Security System Extension" /success:enable

        # V-220777
        auditpol /set /subcategory:"System Integrity" /failure:enable

        # V-220778
        auditpol /set /subcategory:"System Integrity" /success:enable

        # V-220779: the Application event log size must be configured to 32768 KB or greater
        wevtutil sl "Application" /ms:32768000

        # V-220780: the Security event log size must be configured to 1024000 KB or greater
        wevtutil sl "Security" /ms:1024000000

        # V-220781: the System event log size must be configured to 32768 KB or greater
        wevtutil sl "System" /ms:32768000

        # V-220782: the Application event log must be restricted to the following accounts/groups: Eventlog, SYSTEM, Administrators


        # V-220783: the Security event log must be restricted to the following accounts/groups: Eventlog, SYSTEM, Administrators


        # V-220784: the System event log must be restricted to the following accounts/groups: Eventlog, SYSTEM, Administrators


        # V-220785
        auditpol /set /subcategory:"Other Policy Change Events" /success:enable

        # V-220786
        auditpol /set /subcategory:"Other Policy Change Events" /failure:enable

        # V-220787
        auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable

        # V-220787
        auditpol /set /subcategory:"Other Logon/Logoff Events" /failure:enable

        # V-220789
        auditpol /set /subcategory:"Detailed File Share" /success:enable

        # V-220790
        auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable

        # V-220791
        auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /failure:enable

        # V-220809: Command line data must be included in process creation events.
        reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

        # V-220860: PowerShell script block logging must be enabled on Windows 10.
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

        # V-220913: Audit policy using subcategories must be enabled
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f

        # V-220978: the Manage auditing and security log user right must only be assigned to the Administrators group.
        $SecurityTemplate = @"
            [Unicode]
            Unicode=yes
            [Registry Values]
            [Privilege Rights]
            SeSecurityPrivilege = *S-1-5-32-544
            [Version]
            signature=`"`$CHICAGO`$`"
            Revision=1
"@

        $FileName = "V-220978.inf"
        if (Test-Path $FileName) {
            Remove-Item $FileName
            New-Item -ItemType File -Name $FileName | Out-Null
        }
        Add-Content -Value $SecurityTemplate -Path $FileName 
        secedit /configure /db secedit.sdb /cfg $FileName
        Remove-Item $FileName

        # V-250318: PowerShell Transcription must be enabled on Windows 10.
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f
    }

    if ($Source) {
        $SourcePrompt = Read-Host -Prompt "This script will implement the baseline Windows 10 audit policy recommended by $Source.`nDo you want to continue? (y/n)"
        if ($SourcePrompt.ToLower() -eq "y") {
            switch ($Source) {
                "Microsoft" { Set-AuditPolicyUsingMicrosoftRecommendations }
                "Malware Archaeology" { Set-AuditPolicyUsingMalwareArchaeologyRecommendations }
                "DISA" { Set-AuditPolicyUsingTheDisaStigForWindows10 }
            }
        }
    }

    if ($EnableDnsLogging) {
        $EnableDnsLoggingPrompt = Read-Host -Prompt "This script will configure the local DNS client to log all DNS queries. `nDo you want to continue? (y/n)"
        if ($EnableDnsLoggingPrompt.ToLower() -eq "y") {
            wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true   
        }
    } elseif ($DisableDnsLogging) {
        $DisableDnsLoggingPrompt = Read-Host -Prompt "This script will configure the local DNS client to NOT log all DNS queries. `nDo you want to continue? (y/n)"
        if ($DisableDnsLoggingPrompt.ToLower() -eq "y") {
            wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:false  
        }
    }
}


function Set-FirewallPolicy {
    Param(
        [string[]]$AuthorizedProtocol = "ICMP",
        [int[]]$AuthorizedPorts = @(53,80,443,5985),
        [int[]]$RemoteManagementPorts = @(5985),
        [ipaddress]$ManagementIpAddress
    )

    Write-Output "Configuring DoD Windows 10 STIG Requirement V-220725 (Inbound exceptions to the firewall on Windows 10 domain workstations must only allow authorized remote management hosts)."
    
    # enable Windows Remote Management
    Enable-PSRemoting -Force
    if ($ManagementIpAddress) {
        Set-Item -Path WSMan:\localhost\Service\ -Name IPv4Filter -Value $ManagementIpAddress
    }

    # disable all rules allowing inbound connections (except for Windows Remote Management)
    Get-NetFirewallRule -Direction Inbound -Action Allow |
    ForEach-Object { 
        $NotAuthorizedPort = $RemoteManagementPorts -notcontains $($_ | Get-NetFirewallPortFilter).RemotePort
        if ($NotAuthorizedPort) {
            $_ | Set-NetFirewallRule -Enabled False
        }
    }

    # disable all rules allowing outbound connections except for those authorized
    Get-NetFirewallRule -Direction Outbound -Action Allow | 
    ForEach-Object { 
        $NotAuthorizedProtocol = $AuthorizedProtocols -notcontains $($_ | Get-NetFirewallPortFilter).Protocol
        $NotAuthorizedPort = $AuthorizedPorts -notcontains $($_ | Get-NetFirewallPortFilter).RemotePort
        if ($NotAuthorizedProtocol -or $NotAuthorizedPort) {
            $_ | Set-NetFirewallRule -Enabled False
        }
    }
}

function Set-Wallpaper {
    Param(
        [parameter(Mandatory)]$Path
    )

    if (Test-Path $Path) {
        Set-ItemProperty -Path "HKCU:Control Panel\Desktop\" -name WallPaper -value $Path
        rundll32.exe user32.dll, UpdatePerUserSystemParameters
    }
}

function Start-AdBackup {
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [string]$Share = "Backups",
        [string]$Prefix = "AdBackup"
    )
    $BackupFeature = (Install-WindowsFeature -Name Windows-Server-Backup).InstallState
    $BackupServerIsOnline = Test-Connection -ComputerName $ComputerName -Count 2 -Quiet
    if ($BackupFeature -eq "Installed") {
        if ($BackupServerIsOnline) {
            $Date = Get-Date -Format "yyyy-MM-dd"
            $Target = "\\$ComputerName\$Share\$Prefix-$Date"
            $LogDirectory = "C:\BackupLogs"
    	    $LogFile = "$LogDirectory\$Prefix-$Date"
            if (Test-Path $Target) { Remove-Item -Path $Target -Recurse -Force }
            New-Item -ItemType Directory -Path $Target -Force | Out-Null
            if (Test-Path $LogDirectory) { New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null }
            $Expression = "wbadmin START BACKUP -systemState -vssFull -backupTarget:$Target -noVerify -quiet"
            Invoke-Expression $Expression | Out-File -FilePath $LogFile
        } else {
            Write-Output "[x] The computer specified is not online."
        }
    } else {
        Write-Output "[x] The Windows-Server-Backup feature is not installed. Use the command below to install it."
        Write-Output " Install-WindowsFeature -Name Windows-Server-Backup"
    }
}

function Start-Coffee {
    while ($true) {
        (New-Object -ComObject Wscript.Shell).Sendkeys(' '); sleep 60
    }
}

function Start-ImperialMarch {
    [console]::beep(440,500)      
    [console]::beep(440,500)
    [console]::beep(440,500)       
    [console]::beep(349,350)       
    [console]::beep(523,150)       
    [console]::beep(440,500)       
    [console]::beep(349,350)       
    [console]::beep(523,150)       
    [console]::beep(440,1000)
    [console]::beep(659,500)       
    [console]::beep(659,500)       
    [console]::beep(659,500)       
    [console]::beep(698,350)       
    [console]::beep(523,150)       
    [console]::beep(415,500)       
    [console]::beep(349,350)       
    [console]::beep(523,150)       
    [console]::beep(440,1000)
}

function Start-Panic {
    param([string]$ComputerName = 'localhost')
    #shutdown /r /f /m ComputerName /d P:0:1 /c "Your comment"
    Stop-Computer -ComputerName $ComputerName
}

function Start-RollingReboot {
    param(
        [int]$Interval = 4,
        [int]$Duration = 60
    )
    $TaskName = "Rolling Reboot"
    $Action = New-ScheduledTaskAction -Execute "shutdown.exe" -Argument "/r /t 0" 
    $Trigger = New-ScheduledTaskTrigger -At $(Get-Date) -Once -RepetitionInterval $(New-TimeSpan -Minutes $Interval) -RepetitionDuration $(New-TimeSpan -Minutes $Duration)
    $User = 'NT AUTHORITY\SYSTEM' 
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -User $User -RunLevel Highest -Force
    Start-ScheduledTask -TaskName $TaskName
}

function Test-Connections {
    param([Parameter(ValueFromPipeline)][string]$IpAddress)
    Begin{ $IpAddressRange = @() }
    Process{ $IpAddressRange += $IpAddress }
    End{ 
        $Test = $IpAddressRange | ForEach-Object { (New-Object Net.NetworkInformation.Ping).SendPingAsync($_,2000) }
        [Threading.Tasks.Task]::WaitAll($Test)
        $Test.Result | Where-Object { $_.Status -eq 'Success' } | Select-Object @{ Label = 'ActiveIp'; Expression = { $_.Address } }
    }
}

function Test-TcpPort {
    param(
        [Parameter(Mandatory)][ipaddress]$IpAddress,
        [Parameter(Mandatory)][int]$Port
    )
    $TcpClient = New-Object System.Net.Sockets.TcpClient
    $State = $TcpClient.ConnectAsync($IpAddress,$Port).Wait(1000)
    if ($State -eq 'True') { $State = 'Open' }
    else { $State = 'Closed' }
    $TcpPort = [pscustomobject] @{
        'IpAddress' = $IpAddress;
        'Port' = $Port;
        'State' = $State;
    }
    return $TcpPort
}

function Unblock-TrafficToIpAddress {
    param([Parameter(Mandatory)][ipaddress]$IpAddress)
    Remove-NetFirewallRule -DisplayName "Block $IpAddress"
}
