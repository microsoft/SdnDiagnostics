function Get-VfpVMSwitchPort {
    <#
    .SYNOPSIS
        Returns a list of ports from within VFP.
    #>

    try {
        $arrayList = [System.Collections.ArrayList]::new()

        $vfpResults = vfpctrl /list-vmswitch-port
        if ($null -eq $vfpResults) {
            $msg = "Unable to retrieve vmswitch ports from vfpctrl`n{0}" -f $_
            throw New-Object System.NullReferenceException($msg)
        }

        foreach ($line in $vfpResults) {
            $line = $line.Trim()

            if ($line -like 'ITEM LIST' -or $line -ilike '==========='){
                continue
            }

            if ([string]::IsNullOrEmpty($line)) {
                continue
            }

            # lines in the VFP output that contain : contain properties and values
            # need to split these based on count of ":" to build key and values
            if ($line.Contains(":")) {
                [System.String[]]$results = $line.Split(':').Replace(" ", "").Trim()
                if ($results.Count -eq 3) {
                    $key = "$($results[0])-$($results[1])"
                    $value = $results[2]
                }
                elseif ($results.Count -eq 2) {
                    $key = $results[0]
                    $value = $results[1]
                }

                # all groups begin with this property and value so need to create a new psobject when we see these keys
                if ($key -ieq 'Portname') {
                    if ($object) {
                        [void]$arrayList.Add($object)
                    }

                    $object = New-Object -TypeName PSObject
                    $object | Add-Member -MemberType NoteProperty -Name 'PortName' -Value $value

                    continue
                }

                # add the line values to the object
                $object | Add-Member -MemberType NoteProperty -Name $key -Value $value
            }
            elseif ($line.Contains('Command list-vmswitch-port succeeded!')) {
                if ($object) {
                    [void]$arrayList.Add($object)
                }
            }
            else {
                if ($line.Contains('Port is')) {
                    $object | Add-Member -MemberType NoteProperty -Name 'PortState' -Value $line.Split(' ')[2].Replace('.','').Trim()
                }
                elseif ($line.Contains('MAC Learning is')) {
                    $object | Add-Member -MemberType NoteProperty -Name 'MACLearning' -Value $line.Split(' ')[3].Replace('.','').Trim()
                }
                elseif ($line.Contains('NIC is')) {
                    $object | Add-Member -MemberType NoteProperty -Name 'NICState' -Value $line.Split(' ')[2].Replace('.','').Trim()
                }
            }
        }

        return $arrayList
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
