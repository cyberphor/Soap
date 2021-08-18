```
   _____   ____     ___      ____ 
  / ___/  / __ \   /   |    / __ \
  \__ \  / / / /  / /| |   / /_/ /
 ___/ / / /_/ /  / ___ |  / ____/ 
/____/  \____/  /_/  |_| /_/      
   
```
SOAP is a PowerShell module with incident handling and penetration testing functions. 

## Installation
```pwsh
Invoke-WebRequest -Url $URL -Outfile $Outfile
Copy-Item -Path $Outfile -Destination "C:\Program Files\WindowsPowerShell\Modules\"
Import-Module -Name soap
```

## Usage
Once you download and import the PowerShell module, a number of functions will become available. See below for an example of how to invoke one. 
```pwsh
Get-AssetInventory
```
