function Remove-Program {
    $UninstallString = Get-ChildItem "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" |
    ForEach-Object { Get-ItemProperty $_.PsPath } |
    Where-Object { $_.DisplayName -like "" } |
    Select-Object UninstallString
  
    $UninstallString = ($UninstallString -replace 'wscript','').Trim()
    if (Test-Path $UninstallString.Replace('"','')) {
        $WScript = ($UninstallString -split " ")[0]
        Start-Process -FilePath $WScript -ArgumentList $UninstallScript
    }
}

Remove-Program 

# REFERENCE
# https://stackoverflow.com/questions/113542/how-can-i-uninstall-an-application-using-powershell
