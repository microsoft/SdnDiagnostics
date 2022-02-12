# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-NetworkInterfaceLocation {
    param (
        [Parameter(Mandatory = $true)]
        [System.Object]$NetworkControllerNetworkInterfaces,

        [Parameter(Mandatory = $true)]
        [System.Object]$VMNetworkAdapters
    )
    try {
        $networkInterfaces = [System.Collections.ArrayList]::new()

        foreach ($netAdapter in $VMNetworkAdapters) {
            $netInterface = $NetworkControllerNetworkInterfaces | Where-Object {$_.properties.privateMacAddress -eq $netAdapter.MacAddress}

            # if we do not find the MAC address within NC Network Interfaces, skip the placement validation
            if ($null -eq $netInterface) {
                continue
            }

            # if we detect duplicate MAC addresses within the NC Network Interfaces API, skip placement validation
            if ($netInterface.resourceRef.Count -ge 2){
                continue
            }

            # locate the server resource reference for the network interface
            # in some instances, this may be null/empty, so need to handle those instances to prevent script failures
            if($netInterface.properties.server.resourceRef){
                [string]$server = $netInterface.properties.server.resourceRef.Replace('/servers/','')
            }
            else {
                [string]$server = 'NullServerReference'
            }

            if($netAdapter.ComputerName -ne $server){
                $result = [PSCustomObject]@{
                    nc_host = $server
                    hyperv_host = $netAdapter.ComputerName
                    vmName = $netAdapter.VmName
                    macAddress = $netAdapter.MacAddress
                    resourceMetadata = $netInterface.resourceMetadata
                }

                [void]$networkInterfaces.Add($result)
            }
        }

        return $networkInterfaces
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
