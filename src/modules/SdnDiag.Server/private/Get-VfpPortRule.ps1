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
                        $object.Conditions = $subObject

                        $subObject = [PSCustomObject]::new()
                        $subKey = $null
                    }

                    # if <none> is defined for conditions, we can also assume there is nothing to define
                    elseif ($line.Contains('<none>')) {
                        $object.Conditions = $null

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
                        switch -Wildcard ($Layer) {
                            "*_METER_*" {
                                $object = [VfpMeterRule]@{
                                    Rule = $value
                                }
                            }

                            "FW_*" {
                                $object = [VfpFirewallRule]@{
                                    Rule = $value
                                }
                            }

                            "*_ENCAP_*" {
                                $object = [VfpEncapRule]@{
                                    Rule = $value
                                }
                            }

                            "VNET_*" {
                                $object = [VfpVnetRule]@{
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
                            "Unable to add {0} to object. Failing back to use NoteProperty." -f $key | Trace-Output -Level:Warning
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
