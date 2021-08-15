# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-SdnLoadBalancerMuxConfigState {
    <#
    .SYNOPSIS
        Validate that the configurationState and provisioningState is Success
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Uri]$NcUri = $Global:SdnDiagnostics.EnvironmentInfo.NcUrl,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty 
    )

    try {
        "Validating configuration and provisioning state of Load Balancer Muxes" | Trace-Output
        
        if($null -eq $NcUri){
            throw New-Object System.NullReferenceException("Please specify NcUri parameter or execute Get-SdnInfrastructureInfo to populate environment details")
        }

        # if NcRestCredential parameter not defined, check to see if global cache is populated
        if(!$PSBoundParameters.ContainsKey('NcRestCredential')){
            if($Global:SdnDiagnostics.NcRestCredential){
                $NcRestCredential = $Global:SdnDiagnostics.NcRestCredential
            }    
        }

        $status = 'Success'
        $arrayList = [System.Collections.ArrayList]::new()

        $muxes = Get-SdnLoadBalancerMux -NcUri $NcUri.AbsoluteUri -Credential $NcRestCredential
        foreach($object in $muxes){
            if($object.properties.configurationState.status -ine 'Success' -or $object.properties.provisioningState -ine 'Succeeded'){
                $status = 'Failure'

                $details = [PSCustomObject]@{
                    resourceRef = $object.resourceRef
                    provisioningState = $object.properties.provisioningState
                    configurationState = $object.properties.configurationState
                }
    
                [void]$arrayList.Add($details)
            }
        }

        return [PSCustomObject]@{
            Status = $status
            Properties = $arrayList
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}