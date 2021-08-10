# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-LoadBalancerMuxConfigState {
    <#
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Uri]$NcUri = $Global:SdnDiagnostics.EnvironmentInfo.NcUrl,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        "Validating configuration and provisioning state of Load Balancer Muxes" | Trace-Output
        
        if($Global:SdnDiagnostics.Credential){
            $Credential = $Global:SdnDiagnostics.Credential
        }

        $unhealthyNode = $false
        $arrayList = [System.Collections.ArrayList]::new()
        $muxes = Get-SdnLoadBalancerMux -NcUri $NcUri.AbsoluteUri -Credential $Credential

        foreach($object in $muxes){
            if($object.properties.configurationState.status -ine 'Success' -or $object.properties.provisioningState -ine 'Succeeded'){
                $unhealthyNode = $true

                $details = [PSCustomObject]@{
                    resourceRef = $object.resourceRef
                    provisioningState = $object.properties.provisioningState
                    configurationState = $object.properties.configurationState
                }
    
                [void]$arrayList.Add($details)
            }
        }
        
        if($unhealthyNode){
            return [PSCustomObject]@{
                Status = 'Failure'
                Properties = $arrayList
            }
        }
        else {
            return [PSCustomObject]@{
                Status = 'Success'
                Properties = $arrayList
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}