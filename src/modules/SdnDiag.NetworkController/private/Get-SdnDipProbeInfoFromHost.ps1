function Get-SdnDipProbeInfoFromHost {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [IPAddress[]]$HostIPAddress,

        [Parameter(Mandatory = $false)]
        [System.String]$ProbeID = $null
    )

    $slbManager = Connect-SlbManager -ErrorAction Stop
    if ($slbManager) {
        $dipProbeInfo = $slbManager.GetDipProbeInfoFromHost($HostIPAddress, $ProbeID)
        return $dipProbeInfo
    }
}
