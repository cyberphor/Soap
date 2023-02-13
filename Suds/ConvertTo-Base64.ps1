function ConvertTo-Base64 {
  <#
      .SYNOPSIS
      Encodes objects into Base64 strings. 

      .DESCRIPTION
      Encodes UTF-16 Little Endian objects into Base64 string objects.

      .INPUTS
      This function accepts piped objects.

      .OUTPUTS
      System.String.

      .EXAMPLE
      PS> echo "test-connection 8.8.8.8" | ConvertTo-Base64
      dABlAHMAdAAtAGMAbwBuAG4AZQBjAHQAaQBvAG4AIAA4AC4AOAAuADgALgA4AA==
      
      PS> powershell -e dABlAHMAdAAtAGMAbwBuAG4AZQBjAHQAaQBvAG4AIAA4AC4AOAAuADgALgA4AA==
      Source        Destination     IPV4Address      IPV6Address                              Bytes    Time(ms) 
      ------        -----------     -----------      -----------                              -----    -------- 
      LAPTOP-H4T... 8.8.8.8         8.8.4.4                                                   32       18       
      LAPTOP-H4T... 8.8.8.8         8.8.4.4                                                   32       22       
      LAPTOP-H4T... 8.8.8.8         8.8.4.4                                                   32       22       
      LAPTOP-H4T... 8.8.8.8         8.8.4.4                                                   32       17       
  #>
  Param([Parameter(Mandatory, ValueFromPipeline)]$String)
  $Bytes = [System.Text.Encoding]::Unicode.GetBytes($String)
  [Convert]::ToBase64String($Bytes)
}