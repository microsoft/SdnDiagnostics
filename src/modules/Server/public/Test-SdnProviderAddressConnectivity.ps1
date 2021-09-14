function Test-SdnProviderAddressConnectivity {
    <#
    .SYNOPSIS
        Tests whether jumbo packets can be sent between the provider addresses on the current host to the remote provider addresses defined.
    .PARAMETER ProviderAddress
        The IP address assigned to a hidden network adapter in a non-default network compartment
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ProviderAddress
    )

    $maxEncapOverhead = 160
    $defaultMTU = 1500
    $icmpHeader = 28

    $jumboPacket = ($maxEncapOverhead + $defaultMTU) - $icmpHeader
    $standardPacket = $defaultMTU - $icmpHeader

    try {
        $arrayList = [System.Collections.ArrayList]::new()

        $sourceProviderAddress = (Get-ProviderAddress).ProviderAddress
        if ($null -eq $sourceProviderAddress) {
            "No provider addresses returned on {0}" -f $env:COMPUTERNAME | Trace-Output -Level:Error
            return
        }

        $compartmentId = (Get-NetCompartment | Where-Object { $_.CompartmentDescription -ieq 'PAhostVNic' }).CompartmentId
        if ($null -eq $compartmentId) {
            "No compartment returned on {0} that matches description PAhostVNic" -f $env:COMPUTERNAME | Trace-Output -Level:Error
            return
        }

        foreach ($srcAddress in $sourceProviderAddress) {
            if ($srcAddress -ilike "169.*") {
                # if the PA address is an APIPA, it's an indication that host has been added to SDN data plane, however no tenant workloads have yet been provisioned onto the host
                "Skipping validation of {0} as it's an APIPA address" -f $srcAddress | Trace-Output -Level:Warning
                continue
            }

            foreach ($dstAddress in $ProviderAddress) {
                if ($dstAddress -ilike "169.*") {
                    # if the PA address is an APIPA, it's an indication that host has been added to SDN data plane, however no tenant workloads have yet been provisioned onto the host
                    "Skipping validation of {0} as it's an APIPA address" -f $dstAddress | Trace-Output -Level:Warning
                    continue
                }

                $results = Test-Ping -DestinationAddress $dstAddress -SourceAddress $srcAddress -CompartmentId $compartmentId -BufferSize $jumboPacket, $standardPacket -DontFragment   
                [void]$arrayList.Add($results)
            }
        }

        return $arrayList
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
