function Get-SdnVfpPortLayer {
    <#
    .SYNOPSIS
        Enumerates the layers contained within Virtual Filtering Platform (VFP) for specified for the port.
    .PARAMETER PortId
        The Port ID GUID for the network interface.
    .PARAMETER Name
        Returns the specific layer name. If omitted, will return all layers within VFP.
    .EXAMPLE
        PS> Get-SdnVfpPortLayer
    .EXAMPLE
        PS> Get-SdnVfpPortLayer -PortId '2152523D-333F-4082-ADE4-107D8CA75F5B'
    #>

    param (
        [Parameter(Mandatory = $true)]
        [GUID]$PortId,

        [Parameter(Mandatory = $false)]
        [System.String]$Name
    )

    try {
        $arrayList = [System.Collections.ArrayList]::new()
        $vfpLayers = vfpctrl /list-layer /port $PortId
        if ($null -eq $vfpLayers){
            return $null
        }

        # due to how vfp handles not throwing a terminating error if port ID does not exist,
        # need to manually examine the response to see if it contains a failure
        if ($vfpLayers[0] -ilike "ERROR*") {
            "{0}" -f $vfpLayers[0] | Trace-Output -Level:Exception
            return $null
        }

        foreach ($line in $vfpLayers) {
            $line = $line.Trim()

            if ($line -like 'ITEM LIST' -or $line -ilike '==========='){
                continue
            }

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

                    # all layers begin with this property and value so need to create a new psobject when we see these keys
                    if ($key -ieq 'Layer') {
                        if ($object) {
                            [void]$arrayList.Add($object)
                        }

                        $object = New-Object -TypeName PSObject
                        $object | Add-Member -MemberType NoteProperty -Name 'Layer' -Value $value

                        continue
                    }

                    # if the key is priority, we want to declare the value as an int value so we can properly sort the results
                    if ($key -ieq 'Priority') {
                        [int]$value = $value
                    }
                    else {
                        [System.String]$value = $value
                    }
                }

                # add the line values to the object
                $object | Add-Member -MemberType NoteProperty -Name $key -Value $value
            }
            elseif ($line.Contains('Command list-layer succeeded!')) {
                if ($object) {
                    [void]$arrayList.Add($object)
                }
            }
        }

        if ($Name) {
            return ($arrayList | Where-Object { $_.Layer -eq $Name })
        }
        else {
            return ($arrayList | Sort-Object -Property Priority)
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
