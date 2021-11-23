function Set-SdnDiagCache {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$Container,

        [Parameter(Mandatory = $true)]
        [System.String]$Name,

        [Parameter(Mandatory = $true)]
        $Value
    )

    if(-NOT ($Global:SdnDiagnostics.Cache.Contains($Container))) {
        $Global:SdnDiagnostics.Cache.Add($Container, @{})
    }

    if(-NOT ($Global:SdnDiagnostics.Cache[$Container].Contains($Name))) {
        $Global:SdnDiagnostics.Cache[$Container].Add($Name, $Value)
    }
    else {
        $Global:SdnDiagnostics.Cache[$Container][$Name] = $Value
    }
}
