# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

using module .\SdnDiag.Health.psm1

Import-Module $PSScriptRoot\SdnDiag.Health.psm1
Import-Module $PSScriptRoot\SdnDiag.Common.psm1
Import-Module $PSScriptRoot\SdnDiag.Utilities.psm1

##########################
#### CLASSES & ENUMS #####
##########################

##########################
####### FUNCTIONS ########
##########################

function Debug-SdnGateway {
    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if ($_.Scheme -ne "http" -and $_.Scheme -ne "https") {
                throw New-Object System.FormatException("Parameter is expected to be in http:// or https:// format.")
            }
            return $true
        })]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate
    )

    Confirm-IsRasGateway
    $config = Get-SdnModuleConfiguration -Role 'Gateway'
    [string[]]$services = $config.properties.services.Keys
    $healthReport = [SdnRoleHealthReport]@{
        Role = 'Gateway'
    }

    $ncRestParams = $PSBoundParameters

    try {
        $healthReport.HealthTest += @(
            Test-NonSelfSignedCertificateInTrustedRootStore
            Test-DiagnosticsCleanupTaskEnabled -TaskName 'SDN Diagnostics Task'
            Test-ServiceState -ServiceName $services
        )

        # enumerate all the tests performed so we can determine if any completed with Warning or FAIL
        # if any of the tests completed with Warning, we will set the aggregate result to Warning
        # if any of the tests completed with FAIL, we will set the aggregate result to FAIL and then break out of the foreach loop
        # we will skip tests with PASS, as that is the default value
        foreach ($healthStatus in $healthReport.HealthTest) {
            if ($healthStatus.Result -eq 'Warning') {
                $healthReport.Result = $healthStatus.Result
            }
            elseif ($healthStatus.Result -eq 'FAIL') {
                $healthReport.Result = $healthStatus.Result
                break
            }
        }

        return $healthReport

    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
