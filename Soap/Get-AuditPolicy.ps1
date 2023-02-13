function Get-AuditPolicy {
  Param(
      [ValidateSet("System",`
                   "Logon/Logoff",`
                   "Object Access",`
                   "Privilege Use",`
                   "Detailed Tracking",`
                   "Policy Change",`
                   "Account Management",`
                   "DS Access",`
                   "Account Logon"
      )]$Category
  )
  if ($Category -eq $null) {
      $Category = "System",`
                  "Logon/Logoff",`
                  "Object Access",`
                  "Privilege Use",`
                  "Detailed Tracking",`
                  "Policy Change",`
                  "Account Management",`
                  "DS Access",`
                  "Account Logon"    
  }
  $Category | 
  ForEach-Object {
      $Category = $_
      $Policy = @{}
      ((Invoke-Expression -Command 'auditpol.exe /get /category:"$Category"') `
      -split "`r" -match "\S" | 
      Select-Object -Skip 3).Trim() |
      ForEach-Object {
          $Setting = ($_ -replace "\s{2,}","," -split ",")
          $Policy.Add($Setting[0],$Setting[1])
      }
      $Policy.GetEnumerator() |
      ForEach-Object {
          [PSCustomObject]@{
              Subcategory = $_.Key
              Setting = $_.Value
          }
      }
  }
}