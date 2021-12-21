function Get-SdnMuxStats {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$VirtualIP,

        [Parameter(Mandatory = $false)]
        [System.Boolean]$SkipReset = $true
    )

    try {
        $control = Get-MuxDriverControl
        return ($control.GetGlobalStats($SkipReset))
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}