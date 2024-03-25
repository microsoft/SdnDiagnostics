function Test-ResourceConfigurationState {
    <#
    .SYNOPSIS
        Validate that the configurationState of the resources.
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
        "Validating configuration state of {0}" -f $SdnEnvironmentObject.Role.ResourceName | Trace-Output

        $sdnResources = Get-SdnResource -NcUri $SdnEnvironmentObject.NcUrl.AbsoluteUri -Resource $SdnEnvironmentObject.Role.ResourceName -Credential $NcRestCredential
        foreach ($object in $sdnResources) {

            # if we have a resource that is not in a success state, we will skip validation
            # as we do not expect configurationState to be accurate if provisioningState is not Success
            if ($object.properties.provisioningState -ine 'Succeeded') {
                continue
            }

            # examine the configuration state of the resources and display errors to the screen
            $errorMessages = @()
            switch ($object.properties.configurationState.Status) {
                'Warning' {
                    # if we already have a failure, we will not change the result to warning
                    if ($sdnHealthObject.Result -ne 'FAIL') {
                        $sdnHealthObject.Result = 'WARNING'
                    }

                    $traceLevel = 'Warning'
                }

                'Failure' {
                    $sdnHealthObject.Result = 'FAIL'
                    $traceLevel = 'Error'
                }

                'InProgress' {
                    # if we already have a failure, we will not change the result to warning
                    if ($sdnHealthObject.Result -ne 'FAIL') {
                        $sdnHealthObject.Result = 'WARNING'
                    }

                    $traceLevel = 'Warning'
                }

                'Uninitialized' {
                    # in scenarios where state is redundant, we will not fail the test
                    if ($object.properties.state -ieq 'Redundant') {
                        # do nothing
                    }
                    else {
                        # if we already have a failure, we will not change the result to warning
                        if ($sdnHealthObject.Result -ne 'FAIL') {
                            $sdnHealthObject.Result = 'WARNING'
                        }

                        $traceLevel = 'Warning'
                    }
                }

                default {
                    $traceLevel = 'Verbose'
                }
            }

            foreach ($detail in $object.properties.configurationState.detailedInfo) {
                switch ($detail.code) {
                    'Success' {
                        # do nothing
                    }

                    default {
                        $errorMessages += $detail.message
                        try {
                            $errorDetails = Get-HealthData -Property 'ConfigurationStateErrorCodes' -Id $detail.code
                            $sdnHealthObject.Remediation += "[{0}] {1}" -f $object.resourceRef, $errorDetails.Action
                        }
                        catch {
                            "Unable to locate remediation actions for {0}" -f $detail.code | Trace-Output -Level:Warning
                            $remediationString = "[{0}] Examine the configurationState property to determine why configuration failed." -f $object.resourceRef
                            $sdnHealthObject.Remediation += $remediationString
                        }
                    }
                }
            }

            # print the overall configuration state to screen, with each of the messages that were captured
            # as part of the detailedinfo property
            $msg = "{0} is reporting configurationState status {1}:`n`t- {2}" `
                -f $object.resourceRef, $object.properties.configurationState.Status, ($errorMessages -join "`n`t- ")

            $msg | Trace-Output -Level $traceLevel.ToString()

            $details = [PSCustomObject]@{
                resourceRef        = $object.resourceRef
                configurationState = $object.properties.configurationState
            }

            $array += $details
        }

        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
