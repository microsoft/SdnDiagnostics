param(
    [String]$DestinationFolder
)

$outDir = Join-Path -Path $DestinationFolder -ChildPath 'tools'
"Restoring github tools" | Write-Host

if (Test-Path -Path $outDir) {
    Remove-Item -Path $outDir -Recurse -Force
    $null = New-Item -ItemType:Directory -Path $outDir -Force
}

# Put all redistributed and github repos into this directory.
& $PSScriptRoot\build-tools.ps1 -DestinationFolder $outDir

# Check exit code and exit with non-zero exit code so that build will fail.
if($LASTEXITCODE -ne 0){
    "Failed to restore packages correctly" | Write-Error
    exit $LASTEXITCODE
}

exit $LASTEXITCODE
