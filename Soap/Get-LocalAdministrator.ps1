function Get-LocalAdministrator {
  <#
      .EXAMPLE
      Get-LocalAdministrators
      Name         
      ----         
      Administrator
      Cristal      
      Victor 

      .EXAMPLE
      $Computers = (Get-AdComputer -Filter *).Name
      Invoke-Command -ComputerName $Computers -ScriptBlock ${function:Get-LocalAdministrators} |
      Select-Object Name, PsComputerName
  #>
  (net localgroup administrators | Out-String).Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries) |
  Select-Object -Skip 4 |
  Select-String -Pattern "The command completed successfully." -NotMatch |
  ForEach-Object {
      New-Object -TypeName PSObject -Property @{ Name = $_ }
  }
}