function Test-GatewayConfigState {
    <#
    .SYNOPSIS
        Validate that the configurationState and provisioningState is Success
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
	.PARAMETER NcRestCredential
		Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    .EXAMPLE
        PS> Test-GatewayConfigState
    .EXAMPLE
        PS> Test-GatewayConfigState -NcRestCredential (Get-Credential)
    .EXAMPLE
        PS> Test-GatewayConfigState -NcUri "https://nc.contoso.com" -NcRestCredential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()
    $sdnHealthObject.Result = 'PASS'
    $arrayList = [System.Collections.ArrayList]::new()

    try {
        "Validating configuration and provisioning state of Gateways" | Trace-Output

        $gateways = Get-SdnGateway -NcUri $NcUri.AbsoluteUri -Credential $NcRestCredential
        foreach($object in $gateways){
            if($object.properties.configurationState.status -ine 'Success' -or $object.properties.provisioningState -ine 'Succeeded'){
                if($object.properties.configurationState.status -ieq 'Uninitialized'){
                    # do nothing as Uninitialized is an indication the gateway is passive and not hosting any virtual gateways
                }
                else {
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
        $_ | Trace-Exception
    }
}
