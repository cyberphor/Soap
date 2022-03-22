param([parameter(Mandatory)]$Rules)

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

function Send-Alert {
    Param(
        [Parameter(Mandatory, Position = 0)][ValidateSet("Log","Email")][string]$AlertMethod,
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
    if ($AlertMethod -eq "Log") {
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

function Get-Hash {
    param([parameter(Mandatory)]$Object)
    $Stream = ([System.IO.MemoryStream]::New([System.Text.Encoding]::ASCII.GetBytes($Object)))
    $Hash = Get-FileHash -Algorithm MD5 -InputStream $Stream | Select-Object -ExpandProperty Hash
    return $Hash
}

function Invoke-EventFrequencyAnalysis {
    param([parameter(Mandatory)]$Rule)
    $FilterHashTable = @{
        LogName = $Rule.LogName
        Id = $Rule.EventId
        StartTime = $(Get-Date).AddMinutes(-$Rule.Minutes)
    }
    $Events = Get-WinEvent -FilterHashtable $FilterHashTable | 
        Read-WinEvent |
        Where-Object {
            $_.$($Rule.Field) -match $Rule.Value
        }
    $Frequency = $Events.Count
    if ($Frequency -gt $Rule.Threshold) {
        $Properties = [ordered]@{ 
            RuleName = $Rule.Name
            Hash = ""
            Events = @()
        }
        $Alert = New-Object -TypeName psobject -Property $Properties
        $Events | 
        Select-Object -First $Rule.Threshold |
        ForEach-Object {
            $RecordId = $_.EventRecordId
            $Properties = [ordered]@{
                TimeCreated = $_.TimeCreated
                RecordId = $RecordId
                $($Rule.Field) = $_.$($Rule.Field)
            }
            $Alert.Events += $Properties 
        }
        $Alert.Hash = Get-Hash $Events
        $Body = $Alert | ConvertTo-Json
        Send-Alert `
            -AlertMethod Log `
            -Subject $Rule.Name `
            -Body $Body `
            -LogName "Endpoint-Detection" `
            -LogSource "Endpoint-Detection" `
            -LogEntryType Warning `
            -LogEventId 1337
    }
}

function Invoke-EventSpikeAnalysis {}
function Invoke-EventFlatlineAnalysis {}
function Invoke-EventBlacklistAnalysis {}
function Invoke-EventWhitelistAnalysis {}
function Invoke-EventPatternAnalysis {}
function Invoke-EventChangeAnalysis {}
function Invoke-EventNewTermAnalysis {}
function Invoke-EventCardinalityAnalysis {}

function Get-RuleFile {
    param([Parameter(Mandatory)]$Path)
    $Rule = Get-Content $Path | ConvertFrom-Json
    switch ($Rule.type) {
        "frequency" { Invoke-EventFrequencyAnalysis -Rule $Rule }
        "spike" { Invoke-EventSpikeAnalysis -Rule $Rule }
        "flatline" { Invoke-EventFlatlineAnalysis -Rule $Rule }
        "blacklist" { Invoke-EventBlacklistAnalysis -Rule $Rule }
        "whitelist" { Invoke-EventWhitelistAnalysis -Rule $Rule }
        "pattern" { Invoke-EventPatternAnalysis -Rule $Rule }
        "change" { Invoke-EventChangeAnalysis -Rule $Rule }
        "newterm" { Invoke-EventNewTermAnalysis -Rule $Rule }
        "cardinality" { Invoke-EventCardinalityAnalysis -Rule $Rule }
    }
}

if (Test-Path $Rules) {
    $ItemType = (Get-Item -Path $Rules).GetType()
    if ($ItemType -eq [System.IO.DirectoryInfo]) {
        Get-ChildItem -Path $Rules -Recurse |
        ForEach-Object {
            Get-RuleFile -Path $_.FullName
        }
    } else {
        Get-RuleFile -Path $Rules
    }
} else {
    Write-Error "Failed to find $Rules."
}
