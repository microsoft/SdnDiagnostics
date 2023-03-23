function New-WorkingDirectory {
    [CmdletBinding()]
    param ()

    try {
        [System.String]$path = (Get-WorkingDirectory)

        if(-NOT (Test-Path -Path $path -PathType Container)){
            $null = New-Item -Path $path -ItemType Directory -Force
        }

        # create the trace file
        New-TraceOutputFile
    }
    catch {
        $_.Exception | Write-Error
    }
}
