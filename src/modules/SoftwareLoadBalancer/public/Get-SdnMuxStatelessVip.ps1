function Get-SdnMuxStatefulVip {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$VirtualIP
    )

    try {
        $statelessVips = [System.Collections.Generic.List[Microsoft.Cloudnet.Slb.Mux.Driver.VipEndpointKey]]::new()

        $control = Get-MuxDriverControl
        $control.GetStatefulVips($null, [ref]$statelessVips)

        if ($VirtualIP) {
            return ($statelessVips | Where-Object {$_.AddressStr -ieq $VirtualIP})
        }
        else {
            return $statelessVips
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}