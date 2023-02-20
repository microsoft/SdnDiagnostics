param (
    [String]$Version
)

$nugetSpec = Get-Item -Path "$PSScriptRoot\package\Sdndiagnostics.nuspec" | Select-Object -ExpandProperty FullName

$rootDir = (Resolve-Path -LiteralPath "$PSScriptRoot\..\").Path
$outputPackagePath = Join-Path -Path $rootDir -ChildPath "out\packages"

if (Test-Path $outputPackagePath -PathType Container) {
    Write-Host "Removing old packages from package folder $outputPackagePath"
    Remove-Item -Path $outputPackagePath -Recurse -Force
}

$null = New-Item $outputPackagePath -Type Directory -Force

Write-Host "`nBuilding Nuget Package:"
Write-Host "`tSpec file path: $($nugetSpec)"
Write-Host "`tOutput directory: $($outputPackagePath)"
Write-Host "`tVersion: $($Version)`n"

nuget pack $nugetSpec -OutputDirectory $outputPackagePath -properties "version=$Version;rootDir=$rootDir" -NoPackageAnalysis
