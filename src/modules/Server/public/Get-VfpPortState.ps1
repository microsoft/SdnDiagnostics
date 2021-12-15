# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-VfpPortState {
    <#
    .SYNOPSIS
        Returns the current VFP port state for a particular port Id.
    .DESCRIPTION
        Executes 'vfpctrl.exe /get-port-state /port $PortId' to return back the current state of the port specified.
    .PARAMETER PortId
        The Port ID GUID for the network interface.
    .EXAMPLE
        PS> Get-VfpPortState -PortId 3DC59D2B-9BFE-4996-AEB6-2589BD20B559
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [GUID]$PortId,
    )

    try {
        $object = New-Object -TypeName PSObject

        $vfpPortState = vfpctrl.exe /get-port-state /port $PortId
        if ($null -eq $vfpPortState) {
            $msg = "Unable to locate port ID {0} from vfpctrl`n{1}" -f $PortId, $_
            throw New-Object System.NullReferenceException($msg)
        }

        foreach ($line in $vfpPortState) {
            $trimmedLine = $line.Replace(':','').Trim()

            # since we are explicitly looking for true/false in this statement, we will convert the value to boolean when adding to the object
            if ($trimmedLine -match '(.*)\s+(True|False)') {
                $object | Add-Member -MemberType NoteProperty -Name $Matches.1 -Value ([System.Convert]::ToBoolean($Matches.2))
                continue
            }

            # look for enabled/disabled and then seperate out the key/value pairs
            if ($trimmedLine -match '(.*)\s+(Enabled|Disabled)') {
                $object | Add-Member -MemberType NoteProperty -Name $Matches.1 -Value $Matches.2
                continue
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
