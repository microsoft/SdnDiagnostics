function Trace-Exception {
    <#
    .SYNOPSIS
        Extracts information out of exceptions to write to the log file.
        Pipe exceptions to this command in a catch block.

    .PARAMETER Exception
        Any exception inherited from [System.Exception]

    .EXAMPLE
        try
        {
            1 / 0 #divide by 0 exception
        }
        catch
        {
            $_ | Trace-Exception
        }
    #>
    param(
        [parameter(Mandatory = $True, ValueFromPipeline = $true)]
        $Exception
    )

    "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
}
