function Clear-AuditPolicy {
  <#
      .SYNOPSIS
      Clears the local audit policy. 

      .DESCRIPTION
      Uses "auditpol.exe" to clear the local audit (logging) policy. 

      .INPUTS
      None. You cannot pipe objects to this function.

      .OUTPUTS
      None. 

      .EXAMPLE
      PS> Clear-AuditPolicy

      .LINK
      https://github.com/cyberphor/Soap
  #>
  Start-Process -FilePath "auditpol.exe" -ArgumentList "/clear","/y"
}