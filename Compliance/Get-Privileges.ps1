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
        $Sid = $_
        $UserAccount = Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Sid -eq $Sid } | Select-Object -ExpandProperty Name
        $BuiltInAccount = Get-WmiObject -Class Win32_Account | Where-Object { $_.Sid -eq $Sid } | Select-Object -ExpandProperty Name
        $BuiltInGroup = Get-WmiObject -Class Win32_Group | Where-Object { $_.Sid -eq $Sid } | Select-Object -ExpandProperty Name

        if ($UserAccount) {
            $Username = $UserAccount
        } elseif ($BuiltInAccount) {
            $Username = $BuiltInAccount
        } elseif ($BuiltInGroup) {
            $Username = $BuiltInGroup
        } else {
            $Username = $Sid
        }
        
        $Output = New-Object psobject
        Add-Member -InputObject $Output -MemberType NoteProperty -Name Privilege -Value $Privilege
        Add-Member -InputObject $Output -MemberType NoteProperty -Name Sid -Value $_
        Add-Member -InputObject $Output -MemberType NoteProperty -Name Username -Value $Username
        $Output
    }
}
