function Get-Stig {
  <#
      .SYNOPSIS
      Returns STIG rules as PowerShell objects.
              
      .DESCRIPTION
      Returns Security Technical Implementation Guide (STIG) rules as PowerShell objects after reading an Extensible Configuration Checklist Description Format (XCCDF) document.

      .INPUTS
      None. You cannot pipe objects to Get-Stig.

      .OUTPUTS
      PSCustomObject.

      .EXAMPLE
      Get-Stig -Path 'U_MS_Windows_10_STIG_V2R3_Manual-xccdf.xml'

      .LINK
      https://gist.github.com/entelechyIT
  #>
  Param([Parameter(Mandatory)]$Path)
  if (Test-Path $Path) {
      [xml]$XCCDFdocument = Get-Content -Path $Path
      if ($XCCDFdocument.Benchmark.xmlns -like 'http://checklists.nist.gov/xccdf/*') {
          $Stig = @()
          $XCCDFdocument.Benchmark.Group.Rule |
          ForEach-Object {
              $Rule = New-Object -TypeName PSObject -Property ([ordered]@{
                  RuleID    = $PSItem. id
                  RuleTitle = $PSItem.title 
                  Severity = $PSItem.severity
                  VulnerabilityDetails = $($($($PSItem.description) -split '</VulnDiscussion>')[0] -replace '<VulnDiscussion>', '')
                  Check = $PSItem.check.'check-content'
                  Fix = $PSItem.fixtext.'#text'
                  ControlIdentifier = $PSItem.ident.'#text'
                  Control = $null 
              })
              $Stig += $Rule
          }
          return $Stig
      } 
      Write-Error 'The file provided is not a XCCDF document.'
  }
}