function Edit-Module {
  <#
      .SYNOPSIS
      Opens the specified PowerShell module using PowerShell ISE. 

      .DESCRIPTION
      Opens the specified PowerShell script module file (.psm1) using PowerShell ISE. 

      .INPUTS
      None. This function does not accept piped objects.

      .OUTPUTS
      None.

      .EXAMPLE
      PS> Edit-Module "soap"

      .LINK
      https://github.com/cyberphor/Soap
  #>
  Param([Parameter(Mandatory)][string]$Name)
  $Module = Get-Module | Where-Object { $_.Path -like "*$Name.psm1" }
  if ($Module) { 
      ise $Module.Path
  } else {
      Write-Error "A module called '$Name' does not exist."
  }
}