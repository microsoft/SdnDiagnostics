function Get-VfpPortGroup {
    <#
    .SYNOPSIS
        Enumerates the groups contained within the specific Virtual Filtering Platform (VFP) layer specified for the port.

    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [GUID]$PortId,

        [Parameter(Mandatory = $true)]
        [System.String]$Layer
    )

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
                        $object.Conditions = $subObject

                        $subObject = $null
                        $subKey = $null
                    }

                    # if <none> is defined for conditions, we can also assume there is nothing to define
                    elseif ($line.Contains('<none>')) {
                        $object.Conditions = $null

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

                switch ($key) {
                    # group is typically the first property in the output
                    # so we will key off this property to know when to add the object to the array
                    # as well as create a new object
                    'Group' {
                        if ($object) {
                            [void]$arrayList.Add($object)
                        }

                        $object = [VfpGroup]@{
                            Group = $value
                        }
                    }
                    'Friendly Name' { $object.FriendlyName = $value }
                    'Match type' { $object.MatchType = $value }
                    'Conditions' { $subKey = $key }
                    'Priority' { $object.Priority = $value}

                    default {
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
        elseif ($line.Contains('Command list-group succeeded!')) {
            if ($object) {
                [void]$arrayList.Add($object)
            }
        }
    }

    return ($arrayList | Sort-Object -Property Priority)
}
