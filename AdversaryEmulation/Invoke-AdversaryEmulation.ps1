Param (
    [Parameter(Mandatory = $true,ParameterSetName = 'Ad1',Position = 0)]
    [ValidateSet("APT 1","APT 29", "Fox Kitten")]
    [string]
    $Adversary,
    
    [Parameter(Mandatory = $true,ParameterSetName = 'Ad1',Position = 1)]
    [ValidateSet("Reconnaissance","ResourceDevelopment","InitialAccess","Execution","Persistence","PrivilegeEscalation","DefenseEvasion","CredentialAccess","Discovery","LateralMovement","Collection","CommandAndControl","Exfiltration","Impact")]
    [string]$Tactic,
    
    [Parameter(Mandatory = $true,ParameterSetName = 'Ad1',Position = 2)]
    [ValidateSet("ActiveScanning","GatherVictimHostInformation","GatherVictimNetworkInformation")]
    [string]$Technique 
)

if ($Adversary -eq 'APT 1' -and $Tactic -eq 'Reconnaissance') {
    Write-Output $Technique
}
