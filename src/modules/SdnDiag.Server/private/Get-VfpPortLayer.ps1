function Get-VfpPortLayer {
    <#
    .SYNOPSIS
        Enumerates the layers contained within Virtual Filtering Platform (VFP) for specified for the port.
    .PARAMETER PortId
        The Port ID GUID for the network interface
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [GUID]$PortId
    )

    $arrayList = [System.Collections.ArrayList]::new()
    $vfpLayers = vfpctrl /list-layer /port $PortId
    if ($null -eq $vfpLayers){
        return $null
    }

    # due to how vfp handles not throwing a terminating error if port ID does not exist,
    # need to manually examine the response to see if it contains a failure
    if ($vfpLayers[0] -ilike "ERROR*") {
        "{0}" -f $vfpLayers[0] | Trace-Output -Level:Error
        return $null
    }

    foreach ($line in $vfpLayers) {
        $line = $line.Trim()
        if ([string]::IsNullOrEmpty($line)) {
            continue
        }

        # lines in the VFP output that contain : contain properties and values
        # need to split these based on count of ":" to build key and values
        if ($line.Contains(':')) {
            [System.String[]]$results = $line.Split(':').Trim()
            if ($results.Count -eq 2) {
                [System.String]$key = $results[0].Trim()
                [System.String]$value = $results[1].Trim()

                switch ($key) {
                    # layer is typically the first property in the output
                    # so we will key off this property to know when to add the object to the array
                    # as well as create a new object
                    'Layer' {
                        if ($object) {
                            [void]$arrayList.Add($object)
                        }

                        $object = [VfpLayer]@{
                            Layer = $value
                        }
                    }

                    # process the rest of the values as normal
                    'Priority' { $object.Priority = $value}
                    'Friendly name' { $object.FriendlyName = $value}
                    'Flags' { $object.Flags = $value}

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
        else {
            switch -Wildcard ($line) {
                # this should indicate the end of the results from vpctrl
                # if we have an object, add it to the array list
                "*Command list-layer succeeded*" {
                    if ($object) {
                        [void]$arrayList.Add($object)
                    }
                }
            }
        }
    }

    return ($arrayList | Sort-Object -Property Priority)
}
