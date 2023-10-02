function Get-SdnMuxStatelessVip {
    <#
        .SYNOPSIS
            Gets details related to the stateless VIPs.
        .DESCRIPTION
        .PARAMETER VirtualIP
            The Virtual IP address (VIP) of the resource. If omitted, will return all VIPs programmed within the MUX driver.
        .EXAMPLE
            PS> Get-SdnMuxStatelessVip
        .EXAMPLE
            PS> Get-SdnMuxStatelessVip -VirtualIP 100.90.95.42
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$VirtualIP
    )

    try {
        $control = Get-MuxDriverControl
        $statelessVips = [System.Collections.Generic.List[Microsoft.Cloudnet.Slb.Mux.Driver.VipEndpointKey]]::new()

        $control.GetStatelessVips($null, [ref]$statelessVips)

        if ($VirtualIP) {
            return ($statelessVips | Where-Object {$_.AddressStr -ieq $VirtualIP})
        }
        else {
            return $statelessVips
        }
    }
    catch {
       $_ | Trace-Output -Level:Error
    }
}
