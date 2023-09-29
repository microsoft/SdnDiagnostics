function Get-SdnVipConfig {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$VirtualIPAddress
    )

    $slbManager = Connect-SlbManager -ErrorAction Stop
    if ($slbManager) {
        $vipConfig = $slbManager.GetVipConfiguration($VirtualIPAddress)
        return $vipConfig
    }
}
