function Get-SdnCache {
    <#
        .SYNOPSIS
            Returns the cache results stored with the global SdnDiagnostics cache variable
    #>

    param (
        [System.String]$Name
    )

    return $Global:SdnDiagnostics.Cache[$Name]
}
