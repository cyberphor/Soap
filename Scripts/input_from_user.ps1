#!/usr/bin/env pwsh

function Greet-User {
    $Name = Read-Host -Prompt "[+] Your name"
    Write-Host "[+] Hello $Name"
}

Greet-User
