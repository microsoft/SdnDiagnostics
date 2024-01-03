function Get-SdnMuxVipConfig {
    <#
        .SYNOPSIS
            Get configuration details such as the DIPs of the backend resources related to Virtual IP
        .PARAMETER VirtualIP
            The Virtual IP address (VIP) of the resource. If omitted, will return all VIPs programmed within the MUX driver.
        .EXAMPLE
            PS> Get-SdnMuxVipConfig
        .EXAMPLE
            PS> Get-SdnMuxVipConfig -VirtualIP 100.90.95.42
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$VirtualIP
    )

    try {
        $control = Get-MuxDriverControl
        $list = [System.Collections.Generic.List[Microsoft.Cloudnet.Slb.Mux.Driver.VipEndpointConfig]]::new()

        if ($VirtualIP) {
            $statefulVips = Get-SdnMuxStatefulVip -VirtualIp $VirtualIP
        }
        else {
            $statefulVips = Get-SdnMuxStatefulVip
        }

        foreach ($vip in $statefulVips) {
            $vipConfig = New-Object -Type Microsoft.Cloudnet.Slb.Mux.Driver.VipEndpointConfig
            $control.GetVipConfig($vip, [ref]$vipConfig)

            [void]$list.Add($vipConfig)
        }

        return $list
    }
    catch {
        $_ | Trace-Exception
    }
}
