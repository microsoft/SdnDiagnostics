function Test-LoadBalancerMuxConfigState {
    <#
    .SYNOPSIS
        Validate that the configurationState and provisioningState is Success
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
	.PARAMETER NcRestCredential
		Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    .EXAMPLE
        PS> Test-LoadBalancerMuxConfigState
    .EXAMPLE
        PS> Test-LoadBalancerMuxConfigState -NcRestCredential (Get-Credential)
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

    $sdnHealthObject = [SdnHealthResult]::new()
    $sdnHealthObject.Result = 'PASS'
    $arrayList = [System.Collections.ArrayList]::new()

    try {
        "Validating configuration and provisioning state of Load Balancer Muxes" | Trace-Output

        $muxes = Get-SdnLoadBalancerMux -NcUri $NcUri.AbsoluteUri -Credential $NcRestCredential
        foreach($object in $muxes){
            if($object.properties.configurationState.status -ine 'Success' -or $object.properties.provisioningState -ine 'Succeeded'){
                $sdnHealthObject.Result = 'FAIL'

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

        $sdnHealthObject.Properties = $arrayList
        return $sdnHealthObject
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
