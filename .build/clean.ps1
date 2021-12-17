$outDir = "$PSScriptRoot\..\out"
if (Test-Path -Path outDir -PathType Any) {
    "Removing all items under {0}" -f $outDir | Write-Host
    Remove-Item -Path "$outDir\*" -Recurse -Force
}
