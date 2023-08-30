function Get-SdnVipConfig {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$VirtualIPAddress
    )

    $slbManager = Connect-SlbManager
    $vipConfig = $slbManager.GetVipConfiguration($VirtualIPAddress)
    return $vipConfig
}
