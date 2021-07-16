function Test-VMNetAdapterDuplicateMacAddresses {
    param (
        [Parameter(Mandatory = $false)]
        [Uri]$NcUri = $Global:SdnDiagnostics.NcUrl
    )

    try {

    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}