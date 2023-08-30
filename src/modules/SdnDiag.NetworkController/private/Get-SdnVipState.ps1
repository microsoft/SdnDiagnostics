function Get-SdnVipState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [IPAddress]$VirtualIPAddress
    )

    $slbManager = Connect-SlbManager
    $vipState = $slbManager.GetVipState($VirtualIPAddress)
    return $vipState
}
