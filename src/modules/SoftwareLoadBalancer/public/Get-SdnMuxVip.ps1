function Get-SdnMuxVip {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$VirtualIP
    )

    try {
        $vipEndpointKey = [System.Collections.Generic.List[Microsoft.Cloudnet.Slb.Mux.Driver.VipEndpointKey]]::new()

        $control = Get-MuxDriverControl
        $control.GetVips($null, [ref]$vipEndpointKey)

        if ($VirtualIP) {
            return ($vipEndpointKey | Where-Object {$_.AddressStr -ieq $VirtualIP})
        }
        else {
            return $vipEndpointKey
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}