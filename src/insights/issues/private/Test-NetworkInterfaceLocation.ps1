# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-NetworkInterfaceLocation {
    param (
        [System.Object]$NetworkControllerNetworkInterfaces,
        [System.Object]$VMNetworkAdapters
    )
    try {
        $networkInterfaces = [System.Collections.ArrayList]::new()
        foreach($netAdapter in $VMNetworkAdapters){
            $netInterface = $NetworkControllerNetworkInterfaces | Where-Object {$_.properties.privateMacAddress -eq $netAdapter.MacAddress}
            
            # write error to user if we detect duplicate MAC addresses within the NC Network Interfaces API
            # however do not include in the drift detection results as there is a different KI function to check for this
            if($netInterface.resourceRef.Count -ge 2){
                "Detected duplicate MacAddress {0} within Network Controller. Skipping placement validation." -f $netInterface.properties.privateMacAddress[0] | Trace-Output -Level:Error
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
