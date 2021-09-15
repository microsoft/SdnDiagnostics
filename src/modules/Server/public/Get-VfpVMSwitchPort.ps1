function Get-VfpVMSwitchPort {
    <#
    .SYNOPSIS
        Returns a list of ports from within VFP
    #>

    try {
        $arrayList = [System.Collections.ArrayList]::new()
    
        $vfpResults = vfpctrl /list-vmswitch-port
        if ($null -eq $vfpResults) {
            $msg = "Unable to retrieve vmswitch ports from vfpctrl`n{0}" -f $_
            throw New-Object System.NullReferenceException($msg)
        }

        foreach ($line in $vfpResults) {
            # lines in the VFP output that contain : contain properties and values
            # need to split these based on count of ":" to build key and values
            if ($line.Contains(":")) {
                $results = $line.Split(":").Trim().Replace(" ", "")
                if ($results.Count -eq 3) {
                    $key = "$($results[0])-$($results[1])"
                    $value = $results[2]        
                }
                elseif ($results.Count -eq 2) {
                    $key = $results[0]
                    $value = $results[1] 
                }

                # all ports begin with this property and value so need to create a new psobject when we see these keys
                if ($key -eq "Portname") {
                    $port = New-Object -TypeName PSObject
                }

                # add the line values to the object
                $port | Add-Member -MemberType NoteProperty -Name $key -Value $value
            }

            # all the ports are seperated with a blank line
            # use this as our end of properties to add the current obj to the array list
            if ([string]::IsNullOrEmpty($line)) {
                if ($port) {
                    [void]$arrayList.Add($port)
                }
            }
        }

        return $arrayList
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
