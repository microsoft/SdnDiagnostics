function Show-SdnVipState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [IPAddress]$VirtualIPAddress,

        [Parameter(Mandatory = $false)]
        [Switch]$Detailed
    )

    try {
        $slbManager = Connect-SlbManager -ErrorAction Stop
        if ($slbManager) {
            $consolidatedVipState = $slbManager.GetConsolidatedVipState($VirtualIPAddress, $Detailed)
            return $consolidatedVipState
        }
    }
    catch {
        $_ | Trace-Exception
    }
}
