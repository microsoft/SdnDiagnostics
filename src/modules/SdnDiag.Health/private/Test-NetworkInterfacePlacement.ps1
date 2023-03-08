function Test-SdnKINetworkInterfacePlacement {
    <#
    .SYNOPSIS
        Validates the placement of Network Controller Network Interface API placement compared to Hypervisor.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    .EXAMPLE
        PS> Test-SdnKINetworkInterfacePlacement
    .EXAMPLE
        PS> Test-SdnKINetworkInterfacePlacement -Credential (Get-Credential)
    .EXAMPLE
        PS> Test-SdnKINetworkInterfacePlacement -Credential (Get-Credential) -NcRestCredential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    function Test-NetworkInterfaceLocation {
        param (
            [Parameter(Mandatory = $true)]
            [System.Object]$NetworkControllerNetworkInterfaces,

            [Parameter(Mandatory = $true)]
            [System.Object]$VMNetworkAdapters
        )
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

    try {
        "Validate placement of network interfaces between Network Controller and Hypervisor" | Trace-Output

        $issueDetected = $false
        $arrayList = [System.Collections.ArrayList]::new()

        $servers = Get-SdnServer -NcUri $NcUri.AbsoluteUri -ManagementAddressOnly -Credential $NcRestCredential
        $networkInterfaces = Get-SdnResource -NcUri $ncUri.AbsoluteUri -Resource:NetworkInterfaces -Credential $NcRestCredential
        $networkAdapters = Get-SdnVMNetworkAdapter -ComputerName $servers -Credential $Credential -AsJob -Timeout 600 -PassThru
        $driftedNetworkInterfaces = Test-NetworkInterfaceLocation -NetworkControllerNetworkInterfaces $networkInterfaces -VMNetworkAdapters $networkAdapters
        if ($driftedNetworkInterfaces) {
            # we want to focus on instances where network controller api does not have a valid server reference to where the mac address resides
            # this may be false positve if the VM had live migrated recently and nchostagent has not updated network controller
            if ($driftedNetworkInterfaces.nc_host -icontains 'NullServerReference') {
                foreach ($result in $driftedNetworkInterfaces) {
                    "{0}: Network Controller is not aware virtual machine {1} exists on {2}`n`tThis may be a transient exception that can be safely ignored if no issues reported with virtual machine." `
                    -f $result.macAddress, $result.vmName, $result.hyperv_host | Trace-Output -Level:Warning
                }
            }
            else {
                # in this scenario, the serverref and hypervisor server values are mismatched indicating
                # we have a hard drift between network controller and dataplane, which would result in stale/outdated policies
                foreach ($result in $driftedNetworkInterfaces) {
                    "{0}: Network Controller believes {1} exists on {2} while hypervisor is reporting it exists on {3}" `
                    -f $result.macAddress, $result.vmName, $result.nc_host, $result.hyperv_host | Trace-Output -Level:Warning

                    [void]$arrayList.Add($result)
                    $issueDetected = $true
                }
            }
        }

        return [PSCustomObject]@{
            Result = $issueDetected
            Properties = $arrayList
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
