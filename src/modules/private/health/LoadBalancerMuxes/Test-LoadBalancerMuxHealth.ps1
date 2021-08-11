# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-LoadBalancerMuxHealth {
    <#
    #>

    try {
        [Uri]$NcUri = $Global:SdnDiagnostics.EnvironmentInfo.NcUrl

        $Credential = [System.Management.Automation.PSCredential]::Empty

        if($Global:SdnDiagnostics.NcRestCredential){
            $Credential = $Global:SdnDiagnostics.NcRestCredential
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