"Restoring nuget packages for SdnDiagnostics" | Write-Host

$pkgConfig = "$PSScriptRoot\..\packages.config"
$rstrPath = "$PSScriptRoot\..\.packages"

if (!(Test-Path -Path $rstrPath -PathType Container)) {
    $null = New-Item -Path $rstrPath -ItemType Directory -Force
}
else {
    Remove-Item -Path $rstrPath\* -Recurse -Force
}

# Put all redistributed and github repos into this directory.
nuget restore $pkgConfig -OutputDirectory $rstrPath

# Check exit code and exit with non-zero exit code so that build will fail.
if ($LASTEXITCODE -ne 0){
    "Failed to restore packages correctly." | Write-Error
    exit $LASTEXITCODE
}

exit $LASTEXITCODE
