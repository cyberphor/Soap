## How to Get Started with PowerShell Core on Linux
1. Install PowerShell Core
```bash
sudo apt install powershell
```
2. Confirm installation
```bash
which pwsh
```
3. Use a text-editor to create a new file
```bash
vim hello_world.ps1
```
4. Add code to your file
```pwsh
#!/usr/bin/env pwsh

Write-Host 'Hello world!'
```
5. Make your script executable
```bash
chmod +x hello_world.ps1
```
6. Execute your script
```bash
./hello_world.ps1
```
