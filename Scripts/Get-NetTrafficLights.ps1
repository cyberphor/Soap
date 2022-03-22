<#
.SYNOPSIS
    Pings a list of nodes and displays the results using 'traffic light' colors. 
.EXAMPLE
    ./Get-NetTrafficLights.ps1 -File C:\Users\Victor\Desktop\routers.txt
.INPUTS
    A text-file with hostnames and/or IP addresses. 
.OUTPUTS
    Prints text to the console (host).
.LINK
    https://www.yoursecurity.tech
.NOTES
    File name: Get-NetTrafficLights.ps1
    Version: 2.0
    Author: Victor Fernandez III
    Creation Date: Friday, December 13th, 2019
    Purpose: Initial script development
#>

Param(
    [ValidateScript({ Test-Path $_ })]
    [string]$File
)

$Nodes = Get-Content $File 
$Nodes | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Null'
$Nodes | Add-Member -MemberType NoteProperty -Name 'FailedChecks' -Value 'Null'

While ($true) {
    $Nodes | 
    ForEach-Object {
        if ($_.FailedChecks -eq '1') {
            $_.FailedChecks = '2'
            $_.Status = ' Offline ' 
        } 
        elseif (Test-Connection $_ -Count 1 -Quiet) {
            $_.Status = ' Online ' 
        } 
        else {
            $_.FailedChecks = '1'
            $_.Status = ' Standby ' 
        } 
    }
    
    Clear-Host
    Write-Host '----------TRAFFIC LIGHTS----------'
    Write-Host '       '(Get-Date)
    Write-Host '----------------------------------'

    $Nodes | 
    ForEach-Object {
        Write-Host '[' -NoNewline
        if ($_.Status -eq ' Online ') { 
            Write-Host $_.Status -NoNewline -BackgroundColor Green -ForegroundColor Black
        } 
        if ($_.Status -eq ' Offline ') { 
            Write-Host $_.Status -NoNewline -BackgroundColor Red -ForegroundColor Black
        } 
        if ($_.Status -eq ' Standby ') { 
            Write-Host $_.Status -NoNewline -BackgroundColor Yellow -ForegroundColor Black
        }
        Write-Host ']' $_
    } 

    Start-Sleep -Seconds ($Nodes | Measure-Object).Count
}
