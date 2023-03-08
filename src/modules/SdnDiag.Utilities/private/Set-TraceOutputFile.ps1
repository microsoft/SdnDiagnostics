function Set-TraceOutputFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$Path
    )

    $global:SdnDiagnostics.TraceFilePath = $Path.FullName
}
