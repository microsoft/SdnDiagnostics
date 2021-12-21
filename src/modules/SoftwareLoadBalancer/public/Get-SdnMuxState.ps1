function Get-SdnMuxState {
    try {
        return (Get-MuxDriverControl)
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}