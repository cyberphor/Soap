function Get-Privileges {
    SecEdit.exe /export /areas USER_RIGHTS /cfg ./user-rights.txt /quiet
    $Privileges = Get-Content .\user-rights.txt | Where-Object { $_.StartsWith("Se") }
    Remove-Item .\user-rights.txt | Out-Null
    $Privileges |
    ForEach-Object {
        $Assignment = $_.Split(" = ")
        $Privilege = $Assignment[0]
        $Sids = $Assignment[3].Split(",") |
            ForEach-Object {
                if ($_.StartsWith("*")) {
                    $_.Substring(1)
                } else {
                    $_
                }
            }
        $Sids | 
        ForEach-Object {
            $Output = New-Object psobject
            Add-Member -InputObject $Output -MemberType NoteProperty -Name Privilege -Value $Privilege
            Add-Member -InputObject $Output -MemberType NoteProperty -Name Sid -Value $_
            $Output
        }
    }
}

Get-Privileges
