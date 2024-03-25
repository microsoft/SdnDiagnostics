function Get-SdnMuxStatefulVip {
    <#
        .SYNOPSIS
            Gets details related to the stateful VIPs.
        .DESCRIPTION
        .PARAMETER VirtualIP
            The Virtual IP address (VIP) of the resource. If omitted, will return all VIPs programmed within the MUX driver.
        .EXAMPLE
            PS> Get-SdnMuxStatefulVip
        .EXAMPLE
            PS> Get-SdnMuxStatefulVip -VirtualIP 100.90.95.42
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$VirtualIP
    )

    try {
        $control = Get-MuxDriverControl
        $statefulVips = [System.Collections.Generic.List[Microsoft.Cloudnet.Slb.Mux.Driver.VipEndpointKey]]::new()

        $control.GetStatefulVips($null, [ref]$statefulVips)

        if ($VirtualIP) {
            return ($statefulVips | Where-Object {$_.AddressStr -ieq $VirtualIP})
        }
        else {
            return $statefulVips
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
