function Get-VfpPortRule {
    <#
    .SYNOPSIS
        Enumerates the rules contained within the specific group within Virtual Filtering Platform (VFP) layer specified for the port.
    .PARAMETER PortId
        The Port ID GUID for the network interface.
    .PARAMETER Layer
        Specify the target layer.
    .PARAMETER Group
        Specify the group layer.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [GUID]$PortId,

        [Parameter(Mandatory = $true)]
        [System.String]$Layer,

        [Parameter(Mandatory = $true)]
        [System.String]$Group
    )

    $arrayList = [System.Collections.ArrayList]::new()
    $vfpRules = vfpctrl /list-rule /port $PortId /layer $Layer /group $Group
    if ($null -eq $vfpRules){
        return $null
    }

    # due to how vfp handles not throwing a terminating error if port ID does not exist,
    # need to manually examine the response to see if it contains a failure
    if ($vfpRules[0] -ilike "ERROR*") {
        "{0}" -f $vfpRules[0] | Trace-Output -Level:Error
        return $null
    }

    foreach ($line in $vfpRules) {
        $line = $line.Trim()
        if ([string]::IsNullOrEmpty($line)) {
            continue
        }

        # in situations where the value might be nested in another line we need to do some additional data processing
        # subkey is declared below if the value is null after the split
        if ($subKey) {
            $doneProcessingSubKey = $false
            if($null -eq $subObject){
                $subObject = [PSCustomObject]::new()
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
                        $object.Conditions = $subObject

                        $doneProcessingSubKey = $true
                        $subObject = $null
                        $subKey = $null
                    }

                    # if <none> is defined for conditions, we can also assume there is nothing to define
                    elseif ($line.Contains('<none>')) {
                        $object.Conditions = $null

                        $doneProcessingSubKey = $true
                        $subObject = $null
                        $subKey = $null
                    }

                    else {
                        # split the values and add to sub object, that we will then insert into the main object
                        # once we are done processing all the sub values
                        [System.String[]]$subResults = $line.Split(':').Trim()
                        $subObject | Add-Member -MemberType NoteProperty -Name $subResults[0] -Value $subResults[1]
                    }
                }
                'Encap Destination(s)' {
                    # once we reach the next line where we have a ':' we can assume we are done processing the sub value
                    if ($line.Contains(':')) {
                        $object.EncapDestination = $subObject

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
                'Rule Data' {
                    # once we reach the next line where we have a ':' we can assume we are done processing the sub value
                    if ($line.Contains(':')) {
                        $object.RuleData = $subObject

                        $subObject = @()
                        $subKey = $null
                    }
                    else {
                        $subObject += $line.Trim()
                    }
                }
                'Modify' {
                    # this will have a pattern of multiple lines nested under Modify: in which we see a pattern of property:value format
                    # we also see common pattern that Transposition or FlagsEx or Set VLAN is the next property after Conditions, so we can use that to determine when
                    # no further processing is needed for this sub value
                    if ($line.Contains('Transposition') -or $line.Contains('FlagsEx') -or $line.Contains('Set VLAN')) {
                        $object.Modify = $subObject

                        $subObject = [PSCustomObject]::new()
                        $subKey = $null
                    }
                    else {
                        # split the values and add to sub object, that we will then insert into the main object
                        # once we are done processing all the sub values
                        [System.String[]]$subResults = $line.Split(':').Trim()
                        $subObject | Add-Member -MemberType NoteProperty -Name $subResults[0] -Value $subResults[1]
                    }
                }
            }

            if ($doneProcessingSubKey) {
                # we are done processing the subkey, so we can proceed to the rest of the script
            }
            else {
                # we are not done processing the subkey values, so we need to continue to the next line
                continue
            }
        }

        # lines in the VFP output that contain : contain properties and values
        # need to split these based on count of ":" to build key and values
        if ($line.Contains(':')) {
            [System.String[]]$results = $line.Split(':')
            if ($results.Count -eq 2) {
                [System.String]$key = $results[0].Trim()
                [System.String]$value = $results[1].Trim()

                switch ($key) {
                    # rule is typically the first property in the output
                    # so we will key off this property to know when to add the object to the array
                    # as well as create a new object
                    'Rule' {
                        if ($object) {
                            [void]$arrayList.Add($object)
                        }

                        # create the custom object based on the layer
                        # so that we can add appropriate properties
                        switch ($Layer) {
                            "GW_PA_ROUTE_LAYER" {
                                $object = [VfpEncapRule]@{
                                    Rule = $value
                                }
                            }

                            "FW_ADMIN_LAYER_ID" {
                                $object = [VfpFirewallRule]@{
                                    Rule = $value
                                }
                            }

                            "FW_CONTROLLER_LAYER_ID" {
                                $object = [VfpFirewallRule]@{
                                    Rule = $value
                                }
                            }

                            "VNET_METER_LAYER_OUT" {
                                $object = [VfpMeterRule]@{
                                    Rule = $value
                                }
                            }

                            "VNET_MAC_REWRITE_LAYER" {
                                $object = [VfpEncapRule]@{
                                    Rule = $value
                                }
                            }

                            "VNET_ENCAP_LAYER" {
                                $object = [VfpEncapRule]@{
                                    Rule = $value
                                }
                            }

                            "VNET_PA_ROUTE_LAYER" {
                                $object = [VfpEncapRule]@{
                                    Rule = $value
                                }
                            }

                            "SLB_NAT_LAYER" {
                                $object = [VfpRule]@{
                                    Rule = $value
                                }
                            }

                            "SLB_DECAP_LAYER_STATEFUL" {
                                $object = [VfpRule]@{
                                    Rule = $value
                                }
                            }

                            default {
                                $object = [VfpRule]@{
                                    Rule = $value
                                }
                            }
                        }
                    }

                    # because some rules defined within groups do not have a rule name defined such as NAT layers,
                    # grab the friendly name and update the ps object
                    'Friendly name' {
                        if([String]::IsNullOrEmpty($object.Rule)) {
                            $object.Rule = $value
                        }

                        $object.FriendlyName = $value
                    }

                    'Conditions' { $subkey = $key ; continue }
                    'Encap Destination(s)' { $subkey = $key ; continue }
                    'Rule Data' { $subkey = $key ; continue }
                    'Modify' { $subkey = $key ; continue }

                    default {
                        $key = $key.Replace(' ','').Trim()

                        try {
                            $object.$key = $value
                        }
                        catch {
                            # this is the fallback method to just add a property to the object
                            # outside of the defined class properties
                            $object | Add-Member -MemberType NoteProperty -Name $key -Value $value
                            continue
                        }
                    }
                }
            }
        }
        else {
            switch -Wildcard ($line) {
                # this should indicate the end of the results from vpctrl
                # if we have an object, add it to the array list
                "*Command list-rule succeeded*" {
                    if ($object) {
                        [void]$arrayList.Add($object)
                    }
                }
                "*ITEM LIST*" { continue }
                "*====*" { continue }
                default {
                    $object.Properties += $line.Trim()
                }
            }
        }
    }

    return ($arrayList | Sort-Object -Property Priority)
}
