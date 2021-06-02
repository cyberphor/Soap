function Get-FolderPermissions {
    Get-ChildItem |
    ForEach-Object {
        $Path = $_.PsChildName
        $Acl = Get-Acl $_ | Select-Object -ExpandProperty Access
        $Accounts - $Acl.IdentityReference
        $Rights = ($Acl.FileSystemRights -split ',').Trim()
        
        $Rights |
        Select-Object @{Name='Account';Expression={$Account}},@{Name='Right';Expression={$_}},@{Name='Name';Expression={$Path}}
    }
}

Get-FolderPermissions
