<#
.SYNOPSIS
    Enables logging.
.EXAMPLE
    ./Enable-Logging.ps1 -Show logon,firewall
    ./Enable-Logging.ps1 -Show logon,firewall,'process creation'
    ./Enable-Logging.ps1 -Show process
    ./Enable-Logging.ps1 -Set default
    ./Enable-Logging.ps1 -Set logon -Value success
    ./Enable-Logging.ps1 -Set firewall -Value success,failure
.INPUTS
    None.
.OUTPUTS
    None.
.LINK
    https://www.github.com/cyberphor/scripts/PowerShell/Enable-Logging.ps1
.NOTES
    File name: Enabling-Logging.ps1
    Version: 2.0
    Author: Victor Fernandez III
    Creation Date: Tuesday, December 29, 2020
    References:
        https://stackoverflow.com/questions/5648931/test-if-registry-value-exists
        https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_parameter_sets?view=powershell-7.1
        https://stackoverflow.com/questions/13533763/powershell-mandatory-parameter-depends-on-another-parameter
        https://stackoverflow.com/questions/13533763/powershell-mandatory-parameter-depends-on-another-parameter
#>

Param( 
    [Parameter(Mandatory, ParameterSetName = 'Set', Position = 0)][string[]]$Set,
    [Parameter(Mandatory, ParameterSetName = 'Set', Position = 1)][string[]]$Value,
    [Parameter(Mandatory, ParameterSetName = 'Show', Position = 0)][string[]]$Show
)

function Get-AuditpolSettings($Show) {
    $Auditpol = auditpol /get /category:* 
    $AuditpolSettings = @()

    $Auditpol | 
    Select-String 'Success' |
    foreach {
        $Name = ($_ -split 'Success')[0].Trim()
        $Setting = 'Success ' + ($_ -split 'Success')[1].Trim()
        $Category = New-Object psobject
        Add-Member -InputObject $Category -MemberType NoteProperty -Name Category -Value $Name
        Add-Member -InputObject $Category -MemberType NoteProperty -Name Setting -Value $Setting
        $AuditpolSettings = $AuditpolSettings + $Category
    }

    $Auditpol | 
    Select-String 'No Auditing' |
    foreach {
        $Name = ($_ -split 'No Auditing')[0].Trim()
        $Setting = 'No Auditing ' + ($_ -split 'No Auditing')[1].Trim()
        $Category = New-Object psobject
        Add-Member -InputObject $Category -MemberType NoteProperty -Name Category -Value $Name
        Add-Member -InputObject $Category -MemberType NoteProperty -Name Setting -Value $Setting
        $AuditpolSettings = $AuditpolSettings + $Category
    }

    $CmdLineCategory = New-Object psobject
    Add-Member -InputObject $CmdLineCategory -MemberType NoteProperty -Name Category -Value 'Process Creation (Command Line)'
    $Key = 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\'
    $Setting = 'ProcessCreationIncludeCmdLine_Enabled'
    $Value = (Get-ItemProperty $Key).ProcessCreationIncludeCmdLine_Enabled
    if ($Value -eq 1) {
        Add-Member -InputObject $CmdLineCategory -MemberType NoteProperty -Name Setting -Value 'Success' 
    } else { 
        Add-Member -InputObject $CmdLineCategory -MemberType NoteProperty -Name Setting -Value 'No Auditing'
    }
    $AuditpolSettings = $AuditpolSettings + $CmdLineCategory
    
    if ($Show -like 'all') {
        return $AuditpolSettings | Sort-Object -Property Setting -Descending
    } else {
        if ($Show -contains 'firewall') {
            $Show = $Show -replace 'firewall','filter'
        }

        $Show | 
        ForEach-Object {
            $Category = $_
            if ($AuditpolSettings.Category -like $('*' + $Category + '*')) { 
                return $AuditpolSettings | Where-Object { $_.Category -like $('*' + $Category + '*') }
            } 
        } | Sort-Object -Property Setting -Descending   
    }
}

function Set-AuditpolSettings($Set, $Value) {
    $Categories = 
        'Process Creation',
        'File Share',
        'File System',
        'Registry',
        'Filtering Platform Connection'
    
    $Settings = 
        'Success',
        'Success and Failure',
        'No Auditing'

    if ($Categories -contains $Set) {
        if ($Settings -contains $Value) {
            Get-AuditpolSettings $Set
        }
    }
}

if ($Show) {
    Get-AuditpolSettings $Show
} elseif ($Set -and $Value) {
    Set-AuditpolSettings $Set $Value
}
