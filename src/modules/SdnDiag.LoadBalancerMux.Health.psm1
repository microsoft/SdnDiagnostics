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

function Debug-SdnLoadBalancerMux {
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

    Confirm-IsLoadBalancerMux
    $config = Get-SdnModuleConfiguration -Role 'LoadBalancerMux'
    [string[]]$services = $config.properties.services.Keys
    $healthReport = [SdnRoleHealthReport]@{
        Role = 'LoadBalancerMux'
    }

    $ncRestParams = $PSBoundParameters

    try {
        $muxCertRegKey = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SlbMux" -Name MuxCert
        $virtualServers = Get-SdnResource -Resource VirtualServers @ncRestParams
        $muxVirtualServer = $virtualServers | Where-Object {$_.properties.connections.managementaddresses -contains $muxCertRegKey.MuxCert}
        $loadBalancerMux = Get-SdnLoadBalancerMux @ncRestParams | Where-Object {$_.properties.virtualserver.resourceRef -ieq $muxVirtualServer.resourceRef}
        $peerRouters = $loadBalancerMux.properties.routerConfiguration.peerRouterConfigurations.routerIPAddress

        $healthReport.HealthTest += @(
            Test-NonSelfSignedCertificateInTrustedRootStore
            Test-DiagnosticsCleanupTaskEnabled -TaskName 'SDN Diagnostics Task'
            Test-ServiceState -ServiceName $services
            Test-MuxConnectionStateToRouter -RouterIPAddress $peerRouters
            Test-MuxConnectionStateToSlbManager
            Test-NetworkControllerApiNameResolution -NcUri $NcUri
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

function Test-MuxConnectionStateToRouter {
    <#
    SYNOPSIS
        Validates the TCP connectivity for BGP endpoint to the routers.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$RouterIPAddress
    )

    $sdnHealthObject = [SdnHealthTest]::new()

    try {
        foreach ($router in $RouterIPAddress) {
            $tcpConnection = Get-NetTCPConnection -RemotePort 179 -RemoteAddress $router -ErrorAction Ignore
            if ($null -eq $tcpConnection -or $tcpConnection.State -ine 'Established') {
                $sdnHealthObject.Result = 'FAIL'
                $sdnHealthObject.Remediation += "Examine the TCP connectivity for router $router to determine why TCP connection is not established."
            }

            if ($tcpConnection) {
                $sdnHealthObject.Properties += [PSCustomObject]@{
                    NetTCPConnection = $tcpConnection
                }
            }
        }
    }
    catch {
        $sdnHealthObject.Result = 'FAIL'
    }

    return $sdnHealthObject
}

function Test-MuxConnectionStateToSlbManager {
    <#
        SYNOPSIS
        Validates the TCP / TLS connectivity to the SlbManager service.
    #>

    [CmdletBinding()]
    param()

    $sdnHealthObject = [SdnHealthTest]::new()

    try {
        $tcpConnection = Get-NetTCPConnection -LocalPort 8560 -ErrorAction Ignore
        if ($null -eq $tcpConnection -or $tcpConnection.State -ine 'Established') {
            $sdnHealthObject.Result = 'FAIL'
            $sdnHealthObject.Remediation += "Move SlbManager service primary role to another node. Examine the TCP / TLS connectivity for the SlbManager service."
        }

        if ($tcpConnection) {
            $sdnHealthObject.Properties = [PSCustomObject]@{
                NetTCPConnection = $tcpConnection
            }
        }
    }
    catch {
        $sdnHealthObject.Result = 'FAIL'
    }

    return $sdnHealthObject
}
