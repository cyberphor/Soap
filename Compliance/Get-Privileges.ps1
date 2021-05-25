function Get-Privileges {
  SecEdit.exe /export /areas USER_RIGHTS /cfg C:\Users\Public\UserRights.txt
}

Get-Privileges
