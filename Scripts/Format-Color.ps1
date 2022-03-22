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
