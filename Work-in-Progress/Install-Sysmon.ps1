function Install-Sysmon {
  Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
  Expand-Archive -Path "Sysmon.zip" -DestinationPath "C:\Program Files\Sysmon" 
  Remove-Item -Path "Sysmon.zip" -Recurse
  Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Program Files\Sysmon\config.xml"
  Invoke-Expression "C:\'Program Files'\Sysmon\Sysmon64.exe -accepteula -i C:\'Program Files'\Sysmon\config.xml"
}