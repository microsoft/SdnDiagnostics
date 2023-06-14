function Get-VfpVMSwitchPort {
    <#
    .SYNOPSIS
        Returns a list of ports from within VFP.
    #>

    $arrayList = [System.Collections.ArrayList]::new()

    try {
        $vfpResults = vfpctrl /list-vmswitch-port
        if ($null -eq $vfpResults) {
            $msg = "Unable to retrieve vmswitch ports from vfpctrl`n{0}" -f $_
            throw New-Object System.NullReferenceException($msg)
        }

        foreach ($line in $vfpResults) {
            $classProperty = $true
            $line = $line.Trim()

            if ($line -like 'ITEM LIST' -or $line -ilike '==========='){
                continue
            }

            if ([string]::IsNullOrEmpty($line)) {
                continue
            }

            # lines in the VFP output that contain : contain properties and values
            # need to split these based on count of ":" to build key and values
            # some values related to ingress packet drops have multiple ":" so need to account for that
            # example: Ingress Packet Drops: {reason} : {count}
            if ($line.Contains(":")) {
                [System.String[]]$results = $line.Split(':').Replace(" ", "").Trim()
                if ($results.Count -eq 3) {
                    $classProperty = $false
                    $key = "$($results[0])_$($results[1])"
                    $value = $results[2]
                }
                elseif ($results.Count -eq 2) {
                    $classProperty = $true
                    $key = $results[0].Replace('-','').Trim()
                    $value = $results[1]
                }

                # all groups begin with this property and value so need to create a new psobject when we see these keys
                if ($key -ieq 'Portname') {
                    if ($object) {
                        [void]$arrayList.Add($object)
                    }

                    $object = [VfpVmSwitchPort]::new()
                    $object.PortName = $value

                    continue
                }

                # add the line values to the object
                # if we know the key is a class property, just set the value
                # otherwise, add a new member to the object
                if ($classProperty) {
                    try {
                        $object.$key = $value
                    }
                    catch {
                        $object | Add-Member -MemberType NoteProperty -Name $key -Value $value
                    }
                }
                else {
                    $object | Add-Member -MemberType NoteProperty -Name $key -Value $value
                }
            }

            # at this point, we have reached the end of the file, and want to make sure to add the current object into the array list
            elseif ($line.Contains('Command list-vmswitch-port succeeded!')) {
                if ($object) {
                    [void]$arrayList.Add($object)
                }
            }
            else {
                if ($line.Contains('Port is')) {
                    $object.PortState = $line.Split(' ')[2].Replace('.','').Trim()
                }
                elseif ($line.Contains('MAC Learning is')) {
                    $object.MacLearning = $line.Split(' ')[3].Replace('.','').Trim()
                }
                elseif ($line.Contains('NIC is')) {
                    $object.NicState = $line.Split(' ')[2].Replace('.','').Trim()
                }
            }
        }

        return $arrayList
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
