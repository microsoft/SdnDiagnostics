function Test-SdnProviderAddressConnectivity {
    <#
    .SYNOPSIS
        Tests whether jumbo packets can be sent between the provider addresses on the current host to the remote provider addresses defined.
    .PARAMETER ProviderAddress
        The IP address assigned to a hidden network adapter in a non-default network compartment.
    .EXAMPLE
        PS> Test-SdnProviderAddressConnectivity -ProviderAddress (Get-SdnProviderAddress -ComputerName 'Server01','Server02').ProviderAddress
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
            "No provider addresses found" | Trace-Output -Level:Warning
            return
        }

        $compartmentId = (Get-NetCompartment | Where-Object { $_.CompartmentDescription -ieq 'PAhostVNic' }).CompartmentId
        if ($null -eq $compartmentId) {
            "No compartment that matches description PAhostVNic" | Trace-Output -Level:Warning
            return
        }

        foreach ($srcAddress in $sourceProviderAddress) {
            if ($srcAddress -ilike "169.*") {
                # if the PA address is an APIPA, it's an indication that host has been added to SDN data plane, however no tenant workloads have yet been provisioned onto the host
                "Skipping validation of {0} as it's an APIPA address" -f $srcAddress | Trace-Output
                continue
            }

            foreach ($dstAddress in $ProviderAddress) {
                if ($dstAddress -ilike "169.*") {
                    # if the PA address is an APIPA, it's an indication that host has been added to SDN data plane, however no tenant workloads have yet been provisioned onto the host
                    "Skipping validation of {0} as it's an APIPA address" -f $dstAddress | Trace-Output
                    continue
                }

                $results = Test-Ping -DestinationAddress $dstAddress -SourceAddress $srcAddress -CompartmentId $compartmentId -BufferSize $jumboPacket, $standardPacket -DontFragment
                [void]$arrayList.Add($results)
            }
        }

        return $arrayList
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
