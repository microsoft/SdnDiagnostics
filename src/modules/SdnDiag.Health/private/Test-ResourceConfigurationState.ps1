function Test-ResourceConfigurationState {
    <#
    .SYNOPSIS
        Validate that the configurationState and provisioningState is Success
    #>

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
        "Validating configuration state of {0}" -f $ResourceName | Trace-Output
        $sdnResource = Get-SdnResource -NcUri $SdnEnvironmentObject.NcUrl.AbsoluteUri -Resource $ResourceName -Credential $NcRestCredential
        if ($null -ieq $sdnResource) {
            "Unable to locate {0}" -f $ResourceName | Trace-Output -Level:Warning
            return $sdnHealthObject
        }

        # examine the configuration state of the resources and display errors to the screen
        if($sdnResource.properties.configurationState.status -ine 'Success'){
            $errorMessages = @()
            switch ($sdnResource.properties.configurationState.Status) {
                'Warning' {
                    $sdnHealthObject.Result = 'WARNING'
                    $traceLevel = 'Warning'
                }
                'Error' {
                    $sdnHealthObject.Result = 'FAIL'
                    $traceLevel = 'Exception'
                }
                'Uninitialized' {
                    # in scenarios where state is redundant, we will not fail the test
                    # as this is expected to be uninitialized
                    if ($sdnResource.properties.state -ieq 'Redundant') {
                        # do nothing
                    }
                    else {
                        $sdnHealthObject.Result = 'FAIL'
                        $traceLevel = 'Exception'
                    }
                }
                default {
                    $traceLevel = 'Information'
                }
            }

            foreach ($detail in $sdnResource.properties.configurationState.detailedInfo) {
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
                    $sdnHealthObject.Remediation += "Examine the configurationState property to determine why $($sdnResource.resourceRef) configuration failed."
                }
            }

            # print the overall configuration state to screen, with each of the messages that were captured
            # as part of the detailedinfo property
            $msg = "{0} is reporting configurationState status {1}:`n`t- {2}" `
            -f $sdnResource.resourceRef, $sdnResource.properties.configurationState.Status, ($errorMessages -join "`n`t- ")
            $msg | Trace-Output -Level $traceLevel.ToString()
        }

        $details = [PSCustomObject]@{
            resourceRef = $sdnResource.resourceRef
            configurationState = $sdnResource.properties.configurationState
        }

        $sdnHealthObject.Properties = $details
        return $sdnHealthObject
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
