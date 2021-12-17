$outDir = Get-Item -Path "$PSScriptRoot\..\out" -ErrorAction SilentlyContinue
if ($outDir) {
    "Removing all items under {0}" -f $outDir.FullName | Write-Host
    Remove-Item -Path "$($outDir.FullName)\*" -Recurse -Force
}
