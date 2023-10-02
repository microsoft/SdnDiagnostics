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
       $_ | Trace-Output -Level:Error
    }
}
