function Set-TraceOutputFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$Path
    )

    $Script:SdnDiagnostics_Utilities.Cache.TraceFilePath = $Path
}
