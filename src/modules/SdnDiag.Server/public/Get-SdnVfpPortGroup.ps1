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
    .PARAMETER Type
        Specifies an array of IP address families. The cmdlet gets the configuration that matches the address families
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
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [GUID]$PortId,

        [Parameter(Mandatory = $true, ParameterSetName = 'Name')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [System.String]$Layer,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [ValidateSet('IN','OUT')]
        [System.String]$Direction,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [ValidateSet('IPv4','IPv6')]
        [System.String]$Type,

        [Parameter(Mandatory = $false, ParameterSetName = 'Name')]
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
                        # we also see common pattern that Match type is the next property after Conditions, so we can use that to determine when
                        # no further processing is needed for this sub value
                        if ($line.Contains('Match type')) {
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

                        elseif ($line.Contains(':')) {
                            [System.String[]]$subResults = $line.Split(':').Trim()
                            $subObject | Add-Member -MemberType NoteProperty -Name $subResults[0] -Value $subResults[1]
                        }
                    }
                }
            }

            # lines in the VFP output that contain : contain properties and values
            # need to split these based on count of ":" to build key and values
            if ($line.Contains(':')) {
                [System.String[]]$results = $line.Split(':').Trim()
                if ($results.Count -eq 2) {
                    [System.String]$key = $results[0].Trim()
                    [System.String]$value = $results[1].Trim()

                    # all groups begin with this property and value so need to create a new psobject when we see these keys
                    if ($key -ieq 'Group') {
                        if ($object) {
                            [void]$arrayList.Add($object)
                        }

                        $object = New-Object -TypeName PSObject
                        $object | Add-Member -MemberType NoteProperty -Name 'Group' -Value $value

                        continue
                    }

                    if ($key -ieq 'Conditions') {
                        $subKey = $key
                        continue
                    }

                    # if the key is priority, we want to declare the value as an int value so we can properly sort the results
                    if ($key -ieq 'Priority') {
                        [int]$value = $results[1]
                    }

                    # add the line values to the object
                    $object | Add-Member -MemberType NoteProperty -Name $key -Value $value
                }
            }
            elseif ($line.Contains('Command list-group succeeded!')) {
                if ($object) {
                    [void]$arrayList.Add($object)
                }
            }
        }

        if ($Name) {
            return ($arrayList | Where-Object { $_.Group -ieq $Name })
        }

        if ($Direction) {
            $arrayList = $arrayList | Where-Object {$_.Direction -ieq $Direction}
        }

        if ($Type) {
            $arrayList = $arrayList | Where-Object {$_.Type -ieq $Type}
        }

        return ($arrayList | Sort-Object -Property Priority)
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
