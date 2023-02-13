function New-GpoWallpaper {
  Param(
      [Parameter(Mandatory)]$InputFile,
      [Parameter(Mandatory)]$Server
  )
  # create a SMB share on the server
  $Session = New-PSSession -ComputerName $Server
  Invoke-Command -Session $Session -ScriptBlock {
      New-Item -ItemType Directory -Path "C:\Wallpaper"
      New-SmbShare -Name "Wallpaper" -Path "C:\Wallpaper" -FullAccess "Administrators" -ReadAccess "Everyone"
  }
  # copy the wallpaper to the SMB share
  Copy-Item -ToSession $Session -Path $InputFile -Destination "C:\Wallpaper\Wallpaper.jpg"
  # create the GPO 
  $WallpaperPath = "\\$Server\Wallpaper\Wallpaper.jpg"
  $Key = "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System"
  New-GPO -Name "Wallpaper" -Comment "Sets the wallpaper." -ErrorAction Stop
  Set-GPRegistryValue -Name "Wallpaper" -Key $Key -ValueName "Wallpaper" -Value $WallpaperPath -Type "String"
  Set-GPRegistryValue -Name "Wallpaper" -Key $Key -ValueName "WallpaperStyle" -Value "0" -Type "String"
  New-GPLink -Name "Wallpaper" -Target  $(Get-ADDomain -Current LocalComputer).DistinguishedName   
}