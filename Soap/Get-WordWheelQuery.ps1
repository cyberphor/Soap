function Get-WordWheelQuery {
  $Key = "Registry::HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"
  Get-Item $Key | 
  Select-Object -Expand Property | 
  ForEach-Object {
      if ($_ -ne "MRUListEx") {
          $Value = (Get-ItemProperty -Path $Key -Name $_).$_
          [System.Text.Encoding]::Unicode.GetString($Value)
      }
  }
}