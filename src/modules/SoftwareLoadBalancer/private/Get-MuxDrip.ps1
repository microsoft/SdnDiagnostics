function Get-MuxDrip {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$VirtualIP
    )

    try {
        $drips = [System.Collections.Generic.List[Microsoft.Cloudnet.Slb.Mux.Driver.VipConfig]]::new()

        $control = Get-MuxDriverControl
        $control.GetDrips($null , [ref]$drips)

        if ($VirtualIP) {
            return ($drips | Where-Object {$_.AddressStr -ieq $VirtualIP})
        }
        else {
            return $drips
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}