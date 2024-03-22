function Format-NetshTraceProviderAsString {
    <#
        .SYNOPSIS
            Formats the netsh trace providers into a string that can be passed to a netsh command
        .PARAMETER Provider
            The ETW provider in GUID format
        .PARAMETER Level
            Optional. Specifies the level to enable for the corresponding provider.
        .PARAMETER Keywords
            Optional. Specifies the keywords to enable for the corresponding provider.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [guid]$Provider,

        [Parameter(Mandatory=$false)]
        [string]$Level,

        [Parameter(Mandatory=$false)]
        [string]$Keywords
    )

    try {
        [guid]$guid = [guid]::Empty
        if(!([guid]::TryParse($Provider,[ref]$guid))){
            throw "The value specified in the Provider argument must be in GUID format"
        }
        [string]$formattedString = $null
        foreach($param in $PSBoundParameters.GetEnumerator()){
            if($param.Value){
                if($param.Key -ieq "Provider"){
                    $formattedString += "$($param.Key)='$($param.Value.ToString("B"))' "
                }
                elseif($param.Key -ieq "Level" -or $param.Key -ieq "Keywords") {
                    $formattedString += "$($param.Key)=$($param.Value) "
                }
            }
        }

        return $formattedString.Trim()
    }
    catch {
        $_ | Trace-Exception
    }
}
