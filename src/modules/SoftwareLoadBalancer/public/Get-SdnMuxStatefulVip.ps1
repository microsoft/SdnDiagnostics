function Get-SdnMuxStatefulVip {
    <#
        .SYNOPSIS
        .DESCRIPTION
        .PARAMETER VirtualIP
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
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
