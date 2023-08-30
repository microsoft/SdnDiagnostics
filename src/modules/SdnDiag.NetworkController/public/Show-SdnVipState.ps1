function Show-SdnVipState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [IPAddress]$VirtualIPAddress,

        [Parameter(Mandatory = $false)]
        [System.String]$SlbManagerPrimary = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [Switch]$Detailed
    )

    $slbManager = Connect-SlbManager -SlbManagerPrimary $SlbManagerPrimary
    $consolidatedVipState = $slbManager.GetConsolidatedVipState($VirtualIPAddress, $Detailed)
    return $consolidatedVipState
}
