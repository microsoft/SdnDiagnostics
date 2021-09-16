# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-SdnGatewayConfigState {
    <#
    .SYNOPSIS
        Validate that the configurationState and provisioningState is Success
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
	.PARAMETER NcRestCredential
		Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
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
        "Validating configuration and provisioning state of Gateways" | Trace-Output

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

        $gateways = Get-SdnGateway -NcUri $NcUri.AbsoluteUri -Credential $NcRestCredential
        foreach($object in $gateways){
            if($object.properties.configurationState.status -ine 'Success' -or $object.properties.provisioningState -ine 'Succeeded'){
                if($object.properties.configurationState.status -ieq 'Uninitialized'){
                    # do nothing as Uninitialized is an indication the gateway is passive and not hosting any virtual gateways
                }
                else {
                    $status = 'Failure'

                    $details = [PSCustomObject]@{
                        resourceRef = $object.resourceRef
                        provisioningState = $object.properties.provisioningState
                        configurationState = $object.properties.configurationState
                    }

                    [void]$arrayList.Add($details)

                    "{0} is reporting configurationState status: {1} and provisioningState: {2}" `
                        -f $object.resourceRef, $object.properties.configurationState.Status, $object.properties.provisioningState | Trace-Output -Level:Warning
                }
            }
            else {
                "{0} is reporting configurationState status: {1} and provisioningState: {2}" `
                    -f $object.resourceRef, $object.properties.configurationState.Status, $object.properties.provisioningState | Trace-Output -Level:Verbose
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