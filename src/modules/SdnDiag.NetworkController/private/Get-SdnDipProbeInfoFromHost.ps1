function Get-SdnDipProbeInfoFromHost {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [IPAddress]$HostIPAddress,

        [Parameter(Mandatory = $false)]
        [System.String]$ProbeID
    )

    $slbManager = Connect-SlbManager
    $dipProbeInfo = $slbManager.GetDipProbeInfoFromHost($HostIPAddress, $ProbeID)
    return $dipProbeInfo
}
