function Get-SdnMuxVip {
    <#
        .SYNOPSIS
        .DESCRIPTION
        .PARAMETER VirtualIP
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
        $vipEndpointKey = [System.Collections.Generic.List[Microsoft.Cloudnet.Slb.Mux.Driver.VipEndpointKey]]::new()

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
