# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-SdnLoadBalancerMuxConfigState {
    <#
    .SYNOPSIS
        Validate that the configurationState and provisioningState is Success
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
	.PARAMETER NcRestCredential
		Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    .EXAMPLE
        PS> Test-SdnLoadBalancerMuxConfigState
    .EXAMPLE
        PS> Test-SdnLoadBalancerMuxConfigState -NcRestCredential (Get-Credential)
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
        if($null -eq $NcUri){
            throw New-Object System.NullReferenceException("Please specify NcUri parameter or execute Get-SdnInfrastructureInfo to populate environment details")
        }

        # if NcRestCredential parameter not defined, check to see if global cache is populated
        if(!$PSBoundParameters.ContainsKey('NcRestCredential')){
            if($Global:SdnDiagnostics.NcRestCredential){
                $NcRestCredential = $Global:SdnDiagnostics.NcRestCredential
            }
        }

        $insight = Get-InsightDetail -Id '3c505e5c-d207-414e-b326-81d30cbbcc6f' -Type Health
        $insight.Description -f 'Load Balancer Muxes' | Trace-Output

        $arrayList = [System.Collections.ArrayList]::new()

        $muxes = Get-SdnLoadBalancerMux -NcUri $NcUri.AbsoluteUri -Credential $NcRestCredential
        foreach($object in $muxes){
            if($object.properties.configurationState.status -ine 'Success' -or $object.properties.provisioningState -ine 'Succeeded'){
                $insight.Detected = $true

                $details = [PSCustomObject]@{
                    resourceRef = $object.resourceRef
                    provisioningState = $object.properties.provisioningState
                    configurationState = $object.properties.configurationState
                }

                [void]$arrayList.Add($details)

                "{0} is reporting configurationState status: {1} and provisioningState: {2}" `
                    -f $object.resourceRef, $object.properties.configurationState.Status, $object.properties.provisioningState | Trace-Output -Level:Warning
            }
            else {
                "{0} is reporting configurationState status: {1} and provisioningState: {2}" `
                    -f $object.resourceRef, $object.properties.configurationState.Status, $object.properties.provisioningState | Trace-Output -Level:Verbose
            }
        }

        if ($arrayList) {
            $insight.Property = $arrayList
        }

        Set-SdnDiagCache -Container 'Health' -Name $MyInvocation.MyCommand -Value $insight
        return $insight
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
