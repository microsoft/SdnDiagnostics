# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnVfpPortGroup {
    <#
    .SYNOPSIS
        Enumerates the groups contained within the specific Virtual Filtering Platform (VFP) layer specified for the port.
    .PARAMETER PortId
        The Port ID GUID for the network interface.
    .PARAMETER Layer
        Specify the target layer.
    .PARAMETER Direction
        Specify the direction
    .PARAMETER Name
        Returns the specific group name. If omitted, will return all groups within the VFP layer.
    .EXAMPLE
        PS> Get-SdnVfpPortGroup -PortId '2152523D-333F-4082-ADE4-107D8CA75F5B' -Layer 'SLB_NAT_LAYER'
    .EXAMPLE
        PS> Get-SdnVfpPortGroup -PortId '2152523D-333F-4082-ADE4-107D8CA75F5B' -Layer 'SLB_NAT_LAYER' -Name 'SLB_GROUP_NAT_IPv4_IN'
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Name')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Direction')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [GUID]$PortId,

        [Parameter(Mandatory = $true, ParameterSetName = 'Name')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Direction')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [System.String]$Layer,

        [Parameter(Mandatory = $false, ParameterSetName = 'Direction')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [ValidateSet('IN','OUT')]
        [System.String]$Direction,

        [Parameter(Mandatory = $false, ParameterSetName = 'Name')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [System.String]$Name
    )

    try {
        $arrayList = [System.Collections.ArrayList]::new()
        $vfpGroups = vfpctrl /list-group /port $PortId /layer $Layer
        if ($null -eq $vfpGroups){
            return $null
        }

        # due to how vfp handles not throwing a terminating error if port ID does not exist,
        # need to manually examine the response to see if it contains a failure
        if ($vfpGroups[0] -ilike "ERROR*") {
            "{0}" -f $vfpGroups[0] | Trace-Output -Level:Exception
            return $null
        }

        foreach ($line in $vfpGroups) {

            # in situations where the value might be nested in another line we need to do some additional data processing
            # subvalues is declared below if the value is null after the split
            if ($subValues) {
                if (!$subArrayList) {
                    $subArrayList = [System.Collections.ArrayList]::new()
                }

                # if we hit here, we have captured all of the conditions within the group that need processing
                # and we can now add the arraylist to the object and null out the values
                if ($line.Contains('Match type')) {
                    $object | Add-Member -NotePropertyMembers $subArrayList -TypeName $key

                    $subValues = $false
                    $subArrayList = $null
                }
                else {
                    if ($line.Contains(':')) {
                        [System.String[]]$results = $line.Split(':').Trim()
                        if ($results.Count -eq 2) {
                            $subObject = @{
                                $results[0] = $results[1]
                            }

                            [void]$subArrayList.Add($subObject)

                            continue
                        }
                    }
                    elseif ($line.Contains('<none>')) {
                        $object | Add-Member -MemberType NoteProperty -Name $key -Value $null

                        $subValues = $false
                        $subArrayList = $null

                        continue
                    }
                    else {
                        $object | Add-Member -MemberType NoteProperty -Name $key -Value $line.Trim()

                        $subValues = $false
                        $subArrayList = $null

                        continue
                    }
                }
            }

            # lines in the VFP output that contain : contain properties and values
            # need to split these based on count of ":" to build key and values
            if ($line.Contains(':')) {
                [System.String[]]$results = $line.Split(':').Trim()
                if ($results.Count -eq 2) {
                    $key = $results[0]

                    # if the key is priority, we want to declare the value as an int value so we can properly sort the results
                    if ($key -ieq 'Priority') {
                        [int]$value = $results[1]
                    }
                    else {

                        # if we split the object and the second object is null or white space
                        # we can assume that the lines below it have additional data we need to capture and as such
                        # need to do further processing
                        if ([string]::IsNullOrWhiteSpace($results[1])) {
                            $subValues = $true
                            continue
                        }

                        [System.String]$value = $results[1]
                    }
                }

                # all groups begin with this property and value so need to create a new psobject when we see these keys
                if ($key -ieq 'Group') {
                    $object = New-Object -TypeName PSObject
                }

                # add the line values to the object
                $object | Add-Member -MemberType NoteProperty -Name $key -Value $value
            }

            # all the groups are seperated with a blank line
            # use this as our end of properties to add the current obj to the array list
            if ([string]::IsNullOrEmpty($line)) {
                if ($object) {
                    [void]$arrayList.Add($object)
                }
            }
        }

        if ($Name) {
            return ($arrayList | Where-Object { $_.GROUP -ieq $Name })
        }

        if ($Direction) {
            return ($arrayList | Where-Object {$_.Direction -ieq $Direction})
        }

        return ($arrayList | Sort-Object -Property Priority)
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
