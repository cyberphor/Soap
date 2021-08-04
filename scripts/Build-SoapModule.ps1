New-Item -Path "C:\Program Files\WindowsPowerShell\Modules\soap\" -ItemType Directory
New-Item -Path "C:\Program Files\WindowsPowerShell\Modules\soap\soap.psm1"
New-ModuleManifest -Path "C:\Program Files\WindowsPowerShell\Modules\soap\soap.psd1" `
-Author "Victor Fernandez III" `
-RootModule "soap.psm1" `
-Description "Security Operations and Automation via PowerShell (SOAP)"

ise "C:\Program Files\WindowsPowerShell\Modules\soap\soap.psm1"
