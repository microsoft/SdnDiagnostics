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
            $line = $line.Trim()

            if ($line -like 'ITEM LIST' -or $line -ilike '==========='){
                continue
            }

            if ([string]::IsNullOrEmpty($line)) {
                continue
            }

            # in situations where the value might be nested in another line we need to do some additional data processing
            # subkey is declared below if the value is null after the split
            if ($subKey) {
                if($null -eq $subObject){
                    $subObject = New-Object -TypeName PSObject
                }
                if ($null -eq $subArrayList) {
                    $subArrayList = [System.Collections.ArrayList]::new()
                }

                switch ($subKey) {
                    'Conditions' {
                        # this will have a pattern of multiple lines nested under Conditions: in which we see a pattern of property:value format
                        # we also see common pattern that Flow TTL is the next property after Conditions, so we can use that to determine when
                        # no further processing is needed for this sub value
                        if ($line.Contains('Flow TTL')) {
                            $object | Add-Member -NotePropertyMembers @{Conditions = $subObject}

                            $subObject = $null
                            $subKey = $null
                        }

                        # if <none> is defined for conditions, we can also assume there is nothing to define and will just add
                        elseif ($line.Contains('<none>')) {
                            $object | Add-Member -MemberType NoteProperty -Name $subKey -Value 'None'

                            $subObject = $null
                            $subKey = $null
                        }

                        else {
                            [System.String[]]$subResults = $line.Split(':').Trim()
                            $subObject | Add-Member -MemberType NoteProperty -Name $subResults[0] -Value $subResults[1]
                        }
                    }
                    'Encap Destination(s)' {
                        # we typically see a format pattern of {property=value,property=value} for encap destination
                        # and should be contained all within a single line. we also see a matching pattern that FlagsEx is the next property result
                        # so we can use that to determine when no further processing is needed for this sub value
                        if ($line.Contains('FlagsEx')) {
                            $object | Add-Member -MemberType NoteProperty -Name 'Encap Destination' -Value $subObject

                            $subObject = $null
                            $subKey = $null
                        }
                        else {
                            [System.String[]]$subResults = $line.Replace('{','').Replace('}','').Split(',').Trim()
                            foreach ($subResult in $subResults) {
                                [System.String]$subKeyName = $subResult.Split('=')[0].Trim()
                                [System.String]$subKeyValue = $subResult.Split('=')[1].Trim()

                                $subObject | Add-Member -MemberType NoteProperty -Name $subKeyName -Value $subKeyValue
                            }
                        }
                    }
                }

                # since we are processing sub values, we want to move to the next line and not do any further processing
                continue
            }

            # lines in the VFP output that contain : contain properties and values
            # need to split these based on count of ":" to build key and values
            if ($line.Contains(':')) {
                [System.String[]]$results = $line.Split(':')
                if ($results.Count -eq 2) {
                    [System.String]$key = $results[0].Trim()
                    [System.String]$value = $results[1].Trim()

                    # all groups begin with this property and value so need to create a new psobject when we see these keys
                    if ($key -ieq 'RULE') {
                        if ($object) {
                            [void]$arrayList.Add($object)
                        }

                        $object = New-Object -TypeName PSObject
                        $object | Add-Member -MemberType NoteProperty -Name 'Rule' -Value $value

                        continue
                    }

                    # because some rules defined within groups do not have a rule name defined such as NAT layers,
                    # grab the friendly name and update the ps object
                    if ($key -ieq 'Friendly name') {
                        if([String]::IsNullOrEmpty($object.Rule)) {
                            $object.Rule = $value
                        }
                    }

                    if ($key -ieq 'Conditions' -or $key -ieq 'Encap Destination(s)') {
                        $subKey = $key
                        continue
                    }

                    # if the key is priority, we want to declare the value as an int value so we can properly sort the results
                    if ($key -ieq 'Priority') {
                        [int]$value = $value
                    }

                    # add the line values to the object
                    $object | Add-Member -MemberType NoteProperty -Name $key -Value $value
                }
            }
            elseif ($line.Contains('Command list-rule succeeded!')) {
                if ($object) {
                    [void]$arrayList.Add($object)
                }
            }
        }

        if ($Name) {
            return ($arrayList | Where-Object {$_.Rule -ieq $Name -or $_.'Friendly name' -ieq $Name})
        }

        return ($arrayList | Sort-Object -Property Priority)
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
