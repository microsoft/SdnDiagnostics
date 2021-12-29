function Get-SdnMuxStatelessVip {
    <#
        .SYNOPSIS
        .DESCRIPTION
        .PARAMETER VirtualIP
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
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
