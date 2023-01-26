function Get-SdnMuxState {
    <#
        .SYNOPSIS
            This cmdlet retrieves the current state of the load balancer MUX.
        .DESCRIPTION
    #>

    try {
        return (Get-MuxDriverControl)
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
