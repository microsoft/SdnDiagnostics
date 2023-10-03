function Get-SdnVipState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [IPAddress]$VirtualIPAddress
    )

    $slbManager = Connect-SlbManager -ErrorAction Stop
    if ($slbManager) {
        $vipState = $slbManager.GetVipState($VirtualIPAddress)
        return $vipState
    }
}
