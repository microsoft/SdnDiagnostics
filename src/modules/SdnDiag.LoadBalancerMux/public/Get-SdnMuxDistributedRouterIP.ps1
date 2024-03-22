function Get-SdnMuxDistributedRouterIP {
    <#
        .SYNOPSIS
            This cmdlet returns the Distributed Router IPs that are advertised on the MUX.
        .DESCRIPTION
        .PARAMETER VirtualIP
            The Virtual IP address (VIP) of the resource. If omitted, will return all VIPs programmed within the MUX driver.
        .EXAMPLE
            PS> Get-SdnMuxDistributedRouterIP
        .EXAMPLE
            PS> Get-SdnMuxDistributedRouterIP -VirtualIP 100.90.95.42
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$VirtualIP
    )

    try {
        $control = Get-MuxDriverControl

        $vipConfig = [System.Collections.Generic.List[Microsoft.Cloudnet.Slb.Mux.Driver.VipConfig]]::new()
        $control.GetDrips($null , [ref]$vipConfig)

        if ($VirtualIP) {
            return ($vipConfig | Where-Object {$_.AddressStr -ieq $VirtualIP})
        }
        else {
            return $vipConfig
        }
    }
    catch {
        $_ | Trace-Exception
    }
}
