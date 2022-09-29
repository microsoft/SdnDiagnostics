# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnVfpPortRule {
    <#
    .SYNOPSIS
        Enumerates the rules contained within the specific group within Virtual Filtering Platform (VFP) layer specified for the port.
    .PARAMETER PortId
        The Port ID GUID for the network interface.
    .PARAMETER Layer
        Specify the target layer.
    .PARAMETER Group
        Specify the group layer.
    .PARAMETER Name
        Returns the specific rule name. If omitted, will return all rules within the VFP group.
    .EXAMPLE
        PS> Get-SdnVfpPortRule -PortId '2152523D-333F-4082-ADE4-107D8CA75F5B' -Layer 'SLB_NAT_LAYER' -Group 'SLB_GROUP_NAT_IPv4_IN'
    .EXAMPLE
        PS> Get-SdnVfpPortRule -PortId '2152523D-333F-4082-ADE4-107D8CA75F5B' -Layer 'SLB_NAT_LAYER' -Group 'SLB_GROUP_NAT_IPv4_IN' -Name 'SLB_DEFAULT_RULE'
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [GUID]$PortId,

        [Parameter(Mandatory = $true)]
        [System.String]$Layer,

        [Parameter(Mandatory = $true)]
        [System.String]$Group,

        [Parameter(Mandatory = $false)]
        [System.String]$Name
    )

    try {
        $arrayList = [System.Collections.ArrayList]::new()
        $vfpRules = vfpctrl /list-rule /port $PortId /layer $Layer /group $Group
        if ($null -eq $vfpRules){
            return $null
        }

        # due to how vfp handles not throwing a terminating error if port ID does not exist,
        # need to manually examine the response to see if it contains a failure
        if ($vfpRules[0] -ilike "ERROR*") {
            "{0}" -f $vfpRules[0] | Trace-Output -Level:Exception
            return $null
        }

        foreach ($line in $vfpRules) {

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
                        [void]$subArrayList.Add($line.trim())
                        continue
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

                    # all groups begin with this property and value so need to create a new psobject when we see these keys
                    if ($key -ieq 'RULE') {
                        $object = New-Object -TypeName PSObject
                        continue
                    }

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
            return ($arrayList | Where-Object {$_.'Friendly name' -ieq $Name})
        }

        return ($arrayList | Sort-Object -Property Priority)

    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
