function Update-GitHubRepo {
    param(
        [string]$Author,
        [string]$Repo,
        [string]$Branch,
        [string]$Path
    )
    $RepoToUpdate = "https://github.com/$Author/$Repo"
    $Response = Invoke-WebRequest -Uri "$RepoToUpdate/commits"
    if ($Response.StatusCode -eq '200') {
        $LastCommit = ($Response.Links.href | Where-Object { $_ -like "/$Author/$Repo/commit/*" } | Select-Object -First 1).Split("/")[4].Substring(0,7)
        $Git = "$Path\.git\"
        $FETCH_HEAD = "$Git\FETCH_HEAD"
        $LastCommitDownloaded = $null
        if ((Test-Path -Path $Path) -and (Test-Path -Path $Git)) {
            $LastCommitDownloaded = (Get-Content -Path $FETCH_HEAD).SubString(0,7)
        }
        if ($LastCommitDownloaded -ne $LastCommit) {
            Write-Output "[!] Updating the local branch of $Repo."
            Invoke-WebRequest -Uri "$RepoToUpdate/archive/refs/heads/$Branch.zip" -OutFile "$Repo.zip"
            Expand-Archive -Path "$Repo.zip"
            Move-Item -Path "$Repo\$Repo-$Branch" -Destination $Path
            New-Item -Path $FETCH_HEAD -Force | Out-Null
            (Get-Item -Path $Git).Attributes += "Hidden"
            Add-Content -Path $FETCH_HEAD -Value $LastCommit -Force
            Remove-Item -Path "$Repo.zip"
            Remove-Item -Path "$Repo" -Recurse
        } else {
            Write-Output "[+] Nothing to update for the local branch of $Repo."
        }
    }
}