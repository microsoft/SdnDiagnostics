function Test-ResourceProvisioningState {
    <#
    .SYNOPSIS
        Validate that the provisioningState of the resources.
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
        "Validating provisioning state of {0}" -f $SdnEnvironmentObject.Role.ResourceName | Trace-Output

        $sdnResources = Get-SdnResource -NcUri $SdnEnvironmentObject.NcUrl.AbsoluteUri -Resource $SdnEnvironmentObject.Role.ResourceName -Credential $NcRestCredential
        foreach ($object in $sdnResources) {
            # examine the provisioning state of the resources and display errors to the screen
            $msg = "{0} is reporting provisioning state: {1}" -f $object.resourceRef, $object.properties.provisioningState

            switch ($object.properties.provisioningState) {
                'Failed' {
                    $sdnHealthObject.Result = 'FAIL'
                    $msg | Trace-Output -Level:Error

                    $sdnHealthObject.Remediation += "[$($object.resourceRef)] Examine the Network Controller logs to determine why provisioning is $($object.properties.provisioningState)."
                }

                'Updating' {
                    # if we already have a failure, we will not change the result to warning
                    if ($sdnHealthObject.Result -ne 'FAIL') {
                        $sdnHealthObject.Result = 'WARNING'
                    }

                    # since we do not know what operations happened prior to this, we will log a warning
                    # and ask the user to monitor the provisioningState
                    $msg | Trace-Output -Level:Warning
                    $sdnHealthObject.Remediation += "[$($object.resourceRef)] Is reporting $($object.properties.provisioningState). Monitor to ensure that provisioningState moves to Succeeded."
                }

                default {
                    # this should cover scenario where provisioningState is 'Deleting' or Succeeded
                    $msg | Trace-Output -Level:Verbose
                }
            }

            $details = [PSCustomObject]@{
                resourceRef       = $object.resourceRef
                provisioningState = $object.properties.provisioningState
            }

            $array += $details
        }

        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
    }
}
