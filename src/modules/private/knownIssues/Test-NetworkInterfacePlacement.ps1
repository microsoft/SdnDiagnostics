# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-NetworkInterfacePlacement {
    <#
    .SYNOPSIS
        Validates the placement of Network Controller Network Interface API placement compared to Hypervisor.
    #>

    try {
        [Uri]$ncUri = $Global:SdnDiagnostics.EnvironmentInfo.NcUrl

        if($Global:SdnDiagnostics.Credential){
            $Credential = $Global:SdnDiagnostics.Credential
        }
        if($Global:SdnDiagnostics.NcRestCredential){
            $NcRestCredential = $Global:SdnDiagnostics.NcRestCredential
        }

        $issueDetected = $false
        $arrayList = [System.Collections.ArrayList]::new()

        $servers = Get-SdnServer -NcUri $ncUri.AbsoluteUri -ManagementAddressOnly -Credential $NcRestCredential
        $networkInterfaces = Get-SdnResource -NcUri $ncUri.AbsoluteUri -ResourceType:NetworkInterfaces
        $networkAdapters = Get-SdnVMNetAdapter -ComputerName $servers -Credential $Credential -AsJob -Timeout 600 -PassThru
        $driftedNetworkInterfaces = Test-NetworkInterfaceLocation -NetworkControllerNetworkInterfaces $networkInterfaces -VMNetworkAdapters $networkAdapters
        if($driftedNetworkInterfaces){
            # we want to focus on instances where network controller api does not have a valid server reference to where the mac address resides
            # this may be false positve if the VM had live migrated recently and nchostagent has not updated network controller
            if($driftedNetworkInterfaces.nc_host -icontains 'NullServerReference'){
                foreach($result in $driftedNetworkInterfaces){
                    "SDN API is not aware that interface {0} associated with virtual machine {1} exists on {2}`n`tThis may be a transient exception that can be safely ignored if no issues reported with virtual machine." `
                    -f $result.macAddress, $result.vmName, $result.hyperv_host | Trace-Output -Level:Warning
                }
            }
            else {
                # in this scenario, the serverref and hypervisor server values are mismatched indicating 
                # we have a hard drift between network controller and dataplane, which would result in stale/outdated policies
                foreach($result in $driftedNetworkInterfaces){
                    "{0}: Network Controller believes {1} exists on {2} while hypervisor is reporting it exists on {3}" `
                    -f $result.macAddress, $result.vmName, $result.nc_host, $result.hyperv_host | Trace-Output -Level:Error

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