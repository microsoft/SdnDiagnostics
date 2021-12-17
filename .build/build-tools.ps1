param (
    [String]$DestinationFolder
)

if(-NOT (Test-Path -Path $outDir)){
    $null = New-Item -ItemType:Directory -Path $outDir -Force
}

# dynamically pull in tools
$toolsInitProps = Get-Content -Path "$PSScriptRoot\build-tools.json" | ConvertFrom-Json

# region github
foreach ($githubRepo in $toolsInitProps.githubRepo) {
    $destination = Join-Path -Path $outDir -ChildPath $githubRepo.DestinationFolder
    "Cloning $($githubRepo.CloneUri)" | Write-Host                
    "Clearing config for $($githubRepo.CloneUri)" | Write-Host

    if (Test-Path -Path $destination) {
        Remove-Item -Path $destination -Recurse -Force
    }

    git clone $githubRepo.CloneUri $destination

    # keep only the psd1 and psm1 files
    Get-ChildItem -Path $destination -Hidden -Recurse | Remove-Item -Recurse -Force
    Get-ChildItem -Path $destination -Exclude "*.psd1","*.psm1","LICENSE","README.md" -Recurse | Remove-Item -Recurse -Force
}

"Done cloning remote repos to $DestinationFolder" | Write-Host
# endregion github