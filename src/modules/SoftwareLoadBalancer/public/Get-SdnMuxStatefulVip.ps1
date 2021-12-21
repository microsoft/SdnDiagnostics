function Get-SdnMuxStatefulVip {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$VirtualIP
    )

    try {
        $statefulVips = [System.Collections.Generic.List[Microsoft.Cloudnet.Slb.Mux.Driver.VipEndpointKey]]::new()

        $control = Get-MuxDriverControl
        $control.GetStatefulVips($null, [ref]$statefulVips)

        if ($VirtualIP) {
            return ($statefulVips | Where-Object {$_.AddressStr -ieq $VirtualIP})
        }
        else {
            return $statefulVips
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}