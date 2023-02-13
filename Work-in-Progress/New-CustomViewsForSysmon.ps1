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