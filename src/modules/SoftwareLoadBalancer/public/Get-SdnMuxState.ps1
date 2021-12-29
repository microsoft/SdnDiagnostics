function Get-SdnMuxState {
    <#
        .SYNOPSIS
        .DESCRIPTION
    #>

    try {
        return (Get-MuxDriverControl)
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
