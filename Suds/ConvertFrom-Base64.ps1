function ConvertFrom-Base64 {
  <#
      .SYNOPSIS
      Decodes Base64 strings. 

      .DESCRIPTION
      Decodes Base64 string objects into UTF-16 Little Endian objects.

      .INPUTS
      This function accepts piped objects.

      .OUTPUTS
      System.String.

      .EXAMPLE
      PS> "dABlAHMAdAAtAGMAbwBuAG4AZQBjAHQAaQBvAG4AIAA4AC4AOAAuADgALgA4AA==" | ConvertFrom-Base64
      test-connection 8.8.8.8

      .LINK
      https://github.com/cyberphor/Soap
  #>
  Param([Parameter(Mandatory, ValueFromPipeline)]$String)
  [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($String))
}