$nugetSpec = Get-Item -Path "$PSScriptRoot\package\Sdndiagnostics.nuspec" | Select-Object -ExpandProperty FullName

$rootDir = (Resolve-Path -LiteralPath "$PSScriptRoot\..\").Path
$outputPackagePath = "$($rootDir)\out\packages\"
[string]$version = $env:CUSTOM_VERSION

Write-Host "Environment variable CUSTOM_VERSION: $($env:CUSTOM_VERSION)"

if (Test-Path $outputPackagePath -PathType Container) {
    Write-Host "Removing old packages from package folder $outputPackagePath"
    Remove-Item -Path $outputPackagePath -Recurse -Force
}

$null = New-Item $outputPackagePath -Type Directory -Force -Verbose

Write-Host "`nBuilding Nuget Package:"
Write-Host "`tSpec file path: $($nugetSpec)"
Write-Host "`tOutput directory: $($outputPath)"
Write-Host "`tNuget package directory: $($outputPackagePath)"
Write-Host "`tVersion: $($version)`n"

nuget pack $nugetSpec -OutputDirectory $outputPackagePath -properties "version=$version;rootDir=$rootDir" -NoPackageAnalysis
