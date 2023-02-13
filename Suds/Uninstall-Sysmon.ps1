function Uninstall-Sysmon {
  Invoke-Expression "C:\'Program Files'\Sysmon\Sysmon64.exe -u"
  Remove-Item -Path "C:\Program Files\Sysmon" -Recurse -Force
}