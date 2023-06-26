function Test-ResourceConfigurationState {
    <#
    .SYNOPSIS
        Validate that the configurationState and provisioningState is Success
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()
    $array = @()

    try {
        "Validating configuration and provisioning state of {0}" -f $SdnEnvironmentObject.Role.ResourceName | Trace-Output

        $sdnResources = Get-SdnResource -NcUri $SdnEnvironmentObject.NcUrl.AbsoluteUri -Resource $SdnEnvironmentObject.Role.ResourceName -Credential $NcRestCredential
        foreach($object in $sdnResources){
            # examine the provisioning state of the resources and display errors to the screen
            if ($object.properties.provisioningState -ine 'Succeeded') {
                $sdnHealthObject.Result = 'FAIL'
                $sdnHealthObject.Remediation += "Examine the Network Controller logs to determine why $($object.resourceRef) provisioning failed."

                "{0} is reporting provisioning state: {1}" -f $object.resourceRef, $object.properties.provisioningState | Trace-Output -Level:Exception
            }

            # examine the configuration state of the resources and display errors to the screen
            elseif($object.properties.configurationState.status -ine 'Success'){

                # gateways leverage an Uninitialized for when a gateway is passive and not hosting any virtual gateways
                # in this scenario, we can skip this status event
                if($object.properties.configurationState.status -ieq 'Uninitialized'){
                    continue
                }

                $sdnHealthObject.Result = 'FAIL'
                $sdnHealthObject.Remediation += "Examine the configurationState details for $($object.resourceRef) and take corrective action."
                "{0} is reporting configurationState status: {1}" -f $object.resourceRef, $object.properties.configurationState.Status | Trace-Output -Level:Exception
            }

            $details = [PSCustomObject]@{
                resourceRef = $object.resourceRef
                provisioningState = $object.properties.provisioningState
                configurationState = $object.properties.configurationState
            }

            $array += $details
        }

        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
