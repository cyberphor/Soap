filter Read-WinEvent {
  <#
      .EXAMPLE
      Get-WinEvent -FilterHashTable @{LogName="Security";Id=4625} | Read-WinEvent | Select-Object -Property TimeCreated,Hostname,TargetUserName,LogonType | Format-Table -AutoSize
      TimeCreated          TargetUserName LogonType
      -----------          -------------- ---------
      9/12/2021 8:23:27 AM Victor         2        
      9/12/2021 8:23:27 AM Victor         2        
      9/12/2021 7:49:37 AM Victor         2        
      9/12/2021 7:49:37 AM Victor         2
  #>
  $WinEvent = [ordered]@{} 
  $XmlData = [xml]$_.ToXml()
  $SystemData = $XmlData.Event.System
  $SystemData | 
  Get-Member -MemberType Properties | 
  Select-Object -ExpandProperty Name |
  ForEach-Object {
      $Field = $_
      if ($Field -eq 'TimeCreated') {
          $WinEvent.$Field = Get-Date -Format 'yyyy-MM-dd HH:mm:ss K' $SystemData[$Field].SystemTime
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