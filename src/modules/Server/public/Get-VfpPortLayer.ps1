function Get-VfpPortLayer {
    param (
        [Parameter(Mandatory = $true)]
        [GUID]$PortId,

        [Parameter(Mandatory = $false)]
        [System.String]$Name
    )

    try {
        $arrayList = [System.Collections.ArrayList]::new()
        $vfpLayers = vfpctrl /list-layer /port $PortId

        foreach ($line in $vfpLayers) {
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
                        [System.String]$value = $results[1]
                    }
                }
        
                # all layers begin with this property and value so need to create a new psobject when we see these keys
                if ($key -ieq 'Layer') {
                    $object = New-Object -TypeName PSObject
                }
        
                # add the line values to the object
                $object | Add-Member -MemberType NoteProperty -Name $key -Value $value
            }
        
            # all the layers are seperated with a blank line
            # use this as our end of properties to add the current obj to the array list
            if ([string]::IsNullOrEmpty($line)) {
                if ($object) {
                    [void]$arrayList.Add($object)
                }
            }
        }
        
        if ($Name) {
            return ($arrayList | Where-Object { $_.LAYER -eq $Name })
        }
        else {
            return ($arrayList | Sort-Object -Property Priority)
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
