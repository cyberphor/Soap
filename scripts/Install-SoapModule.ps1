$Owner = "cyberphor"
$Repo = "soap"
$RepoFolder = "$Repo\$Repo-main\"
$RepoContents = $RepoFolder + "*"
$Download = $Repo + ".zip"
$ModulesFolder = "C:\Program Files\WindowsPowerShell\Modules\"
$Uri = "https://github.com/$Owner/$Repo/archive/refs/heads/main.zip"
Invoke-WebRequest -Uri $Uri -OutFile $Download
Expand-Archive -Path $Download -DestinationPath $Repo
Move-Item -Path $RepoContents -Destination $Repo
Remove-Item $Download 
Remove-Item $RepoFolder
Move-Item -Path $Repo -Destination $ModulesFolder
Import-Module $Repo -Force
