function Test-ResourceProvisioningState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$ResourceName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()

    try {
        "Validating provisioning state of {0}" -f $ResourceName | Trace-Output
        $sdnResource = Get-SdnResource -NcUri $SdnEnvironmentObject.NcUrl.AbsoluteUri -Resource $ResourceName -Credential $NcRestCredential
        if ($null -ieq $sdnResource) {
            "Unable to locate {0}" -f $ResourceName | Trace-Output -Level:Warning
            return $sdnHealthObject
        }

        # examine the provisioning state of the resources and display errors to the screen
        if ($sdnResources.properties.provisioningState -ine 'Succeeded') {
            $msg = "{0} is reporting provisioning state: {1}" -f $sdnResource.resourceRef, $sdnResource.properties.provisioningState
            switch ($sdnResource.properties.configurationState.Status) {
                'Warning' {
                    $sdnHealthObject.Result = 'WARNING'
                    $msg | Trace-Output -Level:Warning
                }
                'Error' {
                    $sdnHealthObject.Result = 'FAIL'
                    $msg | Trace-Output -Level:Exception
                }
                default {
                    # for all other statuses, we will log as normal
                    $msg | Trace-Output -Level:Information
                }
            }

            $sdnHealthObject.Remediation += "Examine the Network Controller logs to determine why $($sdnResource.resourceRef) provisioning failed."
        }

        $details = [PSCustomObject]@{
            resourceRef = $sdnResource.resourceRef
            provisioningState = $sdnResource.properties.provisioningState
        }

        $sdnHealthObject.Properties = $details
        return $sdnHealthObject
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
