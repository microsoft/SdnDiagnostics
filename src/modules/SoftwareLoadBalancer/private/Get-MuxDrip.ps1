function Get-MuxDrip {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$VirtualIP
    )

    try {
        $vipConfig = [System.Collections.Generic.List[Microsoft.Cloudnet.Slb.Mux.Driver.VipConfig]]::new()

        $control = Get-MuxDriverControl
        $control.GetDrips($null , [ref]$vipConfig)

        if ($VirtualIP) {
            return ($vipConfig | Where-Object {$_.AddressStr -ieq $VirtualIP})
        }
        else {
            return $vipConfig
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}