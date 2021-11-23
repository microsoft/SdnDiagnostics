function Get-SdnDiagCache {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$Container,

        [Parameter(Mandatory = $true)]
        [System.String]$Name
    )

    if ($Global:SdnDiagnostics.Cache.Contains($Container)){
        if ($Global:SdnDiagnostics.Cache[$Container].Contains($Name)){
            return $Global:SdnDiagnostics.Cache[$Container][$Name]
        }
    }

    return $null
}
