function Get-SdnVfpPortState {
    <#
    .SYNOPSIS
        Returns the current VFP port state for a particular port Id.
    .DESCRIPTION
        Executes 'vfpctrl.exe /get-port-state /port $port' to return back the current state of the port specified.
    .PARAMETER PortName
        The port name to return the state for.
    .EXAMPLE
        PS> Get-SdnVfpPortState -PortName 3DC59D2B-9BFE-4996-AEB6-2589BD20B559
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [GUID]$PortName
    )

    try {
        $object = [VfpPortState]::new()

        $vfpPortState = vfpctrl.exe /get-port-state /port $PortName
        if([string]::IsNullOrEmpty($vfpPortState)) {
            $msg = "Unable to locate port {0} from vfpctrl`n{1}" -f $PortName, $_
            return $null
        }

        foreach ($line in $vfpPortState) {
            # skip if the line is empty or null
            if([string]::IsNullOrEmpty($line)) {
                continue
            }

            # skip these as they are not properties we need
            if($line -like "*Port State*" -or $line -ilike "Command get-port-state*"  -or $line -ilike "*====*" -or $line -ilike "*Item List*") {
                continue
            }

            # split the line by the colon and trim the spaces
            # then add to the object which should align with the class properties
            # for anything that cannot be split, will index into a string array
            $subValue = $line.Split(':').Trim().Replace(' ','')
            if ($subValue.Count -eq 2) {
                $object.($subValue[0].ToString()) = ($subValue[1])
            }
            else {
                $object.Properties += $subValue
            }
        }

        return $object
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
