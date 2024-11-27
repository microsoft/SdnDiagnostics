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

function Debug-SdnServer {
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

    $config = Get-SdnModuleConfiguration -Role 'Server'
    $healthReport = [SdnHealthReport]@{
        Role = 'Server'
    }

    $ncRestParams = $PSBoundParameters

    try {
        $serverResource = Get-SdnResource @ncRestParams -Resource:Servers

        $healthReport.HealthValidation += @(
            Test-NonSelfSignedCertificateInTrustedRootStore
            Test-EncapOverhead
            Test-ServerHostId -InstanceId $serverResource.InstanceId
        )

        # enumerate all the tests performed so we can determine if any completed with Warning or FAIL
        # if any of the tests completed with Warning, we will set the aggregate result to Warning
        # if any of the tests completed with FAIL, we will set the aggregate result to FAIL and then break out of the foreach loop
        # we will skip tests with PASS, as that is the default value
        foreach ($healthStatus in $healthReport.HealthValidation) {
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


function Test-EncapOverhead {
    <#
    .SYNOPSIS

    #>

    [CmdletBinding()]
    param ()

    [int]$encapOverheadExpectedValue = 160
    [int]$jumboPacketExpectedValue = 1674 # this is default 1514 MTU + 160 encap overhead
    $sdnHealthObject = [SdnHealthTest]::new()

    try {
        $encapOverheadResults = Get-SdnNetAdapterEncapOverheadConfig
        if ($null -eq $encapOverheadResults) {
            $sdnHealthObject.Result = 'FAIL'
            return $sdnHealthObject
        }

        $encapOverheadResults | ForEach-Object {
            # if encapoverhead is not enabled, this is most commonly due to network adapter firmware or driver
            # recommendations are to update the firmware and driver to the latest version and make sure not using default inbox drivers
            if ($_.EncapOverheadEnabled -eq $false) {

                # in this scenario, encapoverhead is disabled and we have the expected jumbo packet value
                # packets will be allowed to traverse the network without being dropped after adding VXLAN/GRE headers
                if ($_.JumboPacketValue -ge $jumboPacketExpectedValue) {
                    # will not do anything as configuring the jumbo packet is viable workaround if encapoverhead is not supported on the network adapter
                    # this is a PASS scenario
                }

                # in this scenario, encapoverhead is disabled and we do not have the expected jumbo packet value
                # this will result in a failure on the test as it will result in packets being dropped if we exceed default MTU
                if ($_.JumboPacketValue -lt $jumboPacketExpectedValue) {
                    $sdnHealthObject.Result = 'FAIL'
                    $sdnHealthObject.Remediation += "[$($_.NetAdapterInterfaceDescription)] Ensure the latest firmware and drivers are installed to support EncapOverhead. Configure JumboPacket to $jumboPacketExpectedValue if EncapOverhead is not supported."
                }

            }

            # in this case, the encapoverhead is enabled but the value is less than the expected value
            if ($_.EncapOverheadEnabled -and $_.EncapOverheadValue -lt $encapOverheadExpectedValue) {
                # do nothing here at this time as may be expected if no workloads deployed to host
            }
        }

        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-ServerHostId {
    <#
    .SYNOPSIS
        Queries the NCHostAgent HostID registry key value across the hypervisor hosts to ensure the HostID matches known InstanceID results from NC Servers API.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$InstanceId
    )

    $sdnHealthObject = [SdnHealthTest]::new()
    $regkeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters'

    try {
        $regHostId = Get-ItemProperty -Path $regkeyPath -Name 'HostId' -ErrorAction Ignore
        if ($null -ieq $regHostId) {
            $sdnHealthObject.Result = 'FAIL'
            return $sdnHealthObject
        }

        if ($regHostId.HostId -inotin $InstanceId) {
            $sdnHealthObject.Result = 'FAIL'
            $sdnHealthObject.Remediation += "Update the HostId registry under $regkeyPath to match the correct InstanceId from the NC Servers API."
            $sdnHealthObject.Properties = [PSCustomObject]@{
                HostID = $regHostId
            }
        }

        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
