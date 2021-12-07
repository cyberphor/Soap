function Enable-WinRm {
    wmic /node:foo process call create "winrm quickconfig"
}

Enable-WinRm
