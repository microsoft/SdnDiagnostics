function Get-SdnMuxVip {
    <#
        .SYNOPSIS
            This cmdlet returns the VIP endpoint(s).
        .DESCRIPTION
        .PARAMETER VirtualIP
            The Virtual IP address (VIP) of the resource. If omitted, will return all VIPs programmed within the MUX driver.
        .EXAMPLE
            PS> Get-SdnMuxVip
        .EXAMPLE
            PS> Get-SdnMuxVip -VirtualIP 100.90.95.42
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$VirtualIP
    )

    try {
        $control = Get-MuxDriverControl
        $vipConfig = [System.Collections.Generic.List[Microsoft.Cloudnet.Slb.Mux.Driver.VipConfig]]::new()

        $control.GetVips($null, [ref]$vipConfig)

        if ($VirtualIP) {
            return ($vipConfig | Where-Object {$_.AddressStr -ieq $VirtualIP})
        }
        else {
            return $vipConfig
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
