# takes in user input; ex: phrase or word
# gets the hex version of their input
# strips white spaces
# gets the total number of individual hex characters
# checks if total number of single hex characters are less than 56 (output = yes or no)
# prints everything: raw string/usability, number of characters, string hex

function i_put_a_spell_on_you {
    $Message = Read-Host -Prompt '[>] Your message'
    $Hex = ($Message |
        Format-Hex -Encoding UTF8 |
        Select -ExpandProperty Bytes |
        ForEach-Object { '{0:x2}' -f $_ }) -join ''
    $Length = $Hex.Length

    if ($Length -lt 56) { $Usablility = "will fit." }
    else { $Usablility = "will not fit" }

    Clear-Host
    Write-Output "[>] '$Message' $Usablility `n"
    Write-Output "[>] Number of individual characters: $Length `n"
    Write-Output "[>] Hex: $Hex `n"
}

i_put_a_spell_on_you
