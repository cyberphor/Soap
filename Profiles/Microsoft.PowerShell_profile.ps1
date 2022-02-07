Import-Module PSCyberTools
$host.ui.rawui.WindowTitle = "Terminal"
function prompt { 'PS ' + ($pwd -split '\\')[0]+' '+$(($pwd -split '\\')[-1] -join '\') + '> ' }
Set-Location -Path "C:\Users\$env:USERNAME\Desktop"
