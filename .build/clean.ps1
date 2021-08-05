$pathsToClear = "$PSScriptRoot\..\out"

foreach($path in $pathsToClear) {
    if(Test-Path -Path $path) {
        "Removing all items under $path" | Write-Host
        Remove-Item -Path $path -Recurse -Force
    }
}