function Get-VfpPortRule {
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
            # return ($arrayList | Where-Object {$_.GROUP -eq $Name})
        }
        else {
            return ($arrayList | Sort-Object -Property Priority)
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
