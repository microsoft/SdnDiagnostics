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
                $msg = "{0} is reporting provisioning state: {1}" -f $object.resourceRef, $object.properties.provisioningState
                switch ($object.properties.configurationState.Status) {
                    'Warning' {
                        $msg | Trace-Output -Level:Warning
                    }
                    'Error' {
                        $msg | Trace-Output -Level:Exception
                    }
                    default {
                        # for all other statuses, we will log to verbose
                        $msg | Trace-Output -Level:Verbose
                    }
                }

                $sdnHealthObject.Result = 'FAIL'
                $sdnHealthObject.Remediation += "Examine the Network Controller logs to determine why $($object.resourceRef) provisioning failed."

                # we can continue to the next object at this point
                # as we do not care about the configurationState at this point if the provisioningState is not success
                continue
            }

            # examine the configuration state of the resources and display errors to the screen
            elseif($object.properties.configurationState.status -ine 'Success'){
                $errorMessages = @()
                switch ($object.properties.configurationState.Status) {
                    'Warning' {
                        $traceLevel = 'Warning'
                    }
                    'Error' {
                        $traceLevel = 'Exception'
                    }
                    'Uninitialized' {
                        # in scenarios where state is redundant, we will not fail the test
                        # as this is expected to be uninitialized
                        if ($object.properties.state -ieq 'Redundant') {
                            continue
                        }
                        else {
                            $traceLevel = 'Exception'
                        }
                    }
                    default {
                        $traceLevel = 'Information'
                    }
                }

                $sdnHealthObject.Result = 'FAIL'
                foreach ($detail in $object.properties.configurationState.detailedInfo) {
                    if ($detail.code -eq 'Success') {
                        continue
                    }

                    switch ($detail.code) {
                        'Success' {
                            continue
                        }
                        default {
                            $errorMessages += $detail.message
                        }
                    }

                    try {
                        $errorDetails = Get-HealthData -Property 'ConfigurationStateErrorCodes' -Id $detail.code
                        $sdnHealthObject.Remediation += $errorDetails.Action
                    }
                    catch {
                        "Unable to locate remediation actions for {0}" -f $detail.code | Trace-Output -Level:Warning
                        $sdnHealthObject.Remediation += "Examine the configurationState property to determine why $($object.resourceRef) configuration failed."
                    }
                }

                # print the overall configuration state to screen, with each of the messages that were captured
                # as part of the detailedinfo property
                $msg = "{0} is reporting configurationState status {1}:`n`t- {2}" `
                -f $object.resourceRef, $object.properties.configurationState.Status, ($errorMessages -join "`n`t- ")

                $msg | Trace-Output -Level:$traceLevel
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
