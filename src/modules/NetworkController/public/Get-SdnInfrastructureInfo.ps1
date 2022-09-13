# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnInfrastructureInfo {
    <#
    .SYNOPSIS
        Get the SDN infrastructure information from network controller. The function will update the $Global:SdnDiagnostics.EnvironmentInfo variable.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER NcRestCredential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER Force
        Switch parameter to force a refresh of the environment cache details
    .EXAMPLE
        PS> Get-SdnInfrastructureInfo
    .EXAMPLE
        PS> Get-SdnInfrastructureInfo -NetworkController 'NC01' -Credential (Get-Credential) -NcRestCredential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]$NetworkController = $(HostName),

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [ValidateScript({
            if ($_.Scheme -ne "http" -and $_.Scheme -ne "https") {
                throw New-Object System.FormatException("Parameter is expected to be in http:// or https:// format.")
            }
            return $true
        })]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [Switch]$Force
    )

    try {

        # if force is defined, purge the cache to force a refresh on the objects
        if ($PSBoundParameters.ContainsKey('Force')) {
            $Global:SdnDiagnostics.EnvironmentInfo.NcUrl = $null
            $global:SdnDiagnostics.EnvironmentInfo.NetworkController = $null
            $global:SdnDiagnostics.EnvironmentInfo.SoftwareLoadBalancer = $null
            $Global:SdnDiagnostics.EnvironmentInfo.Gateway = $null
            $Global:SdnDiagnostics.EnvironmentInfo.Server = $null
            $Global:SdnDiagnostics.EnvironmentInfo.FabricNodes = $null
        }

        # get the NC Northbound API endpoint
        if ($NcUri) {
            $Global:SdnDiagnostics.EnvironmentInfo.NcUrl = $NcUri.AbsoluteUri
        }
        elseif ([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.EnvironmentInfo.NcUrl)) {
            $result = Get-SdnNetworkControllerRestURL -NetworkController $NetworkController -Credential $Credential

            if ($null -eq $result) {
                throw New-Object System.NullReferenceException("Unable to locate REST API endpoint for Network Controller. Please specify REST API with -RestUri parameter.")
            }

            $Global:SdnDiagnostics.EnvironmentInfo.NcUrl = $result
        }

        # get the supported rest API versions from network controller
        # as we default this to v1 on module import within $Global.SdnDiagnostics, will not check to see if null first
        $Global:SdnDiagnostics.EnvironmentInfo.RestApiVersion = (Get-SdnDiscovery -NcUri $Global:SdnDiagnostics.EnvironmentInfo.NcUrl -Credential $NcRestCredential).properties.currentRestVersion

        # get the network controllers
        if ([System.String]::IsNullOrEmpty($global:SdnDiagnostics.EnvironmentInfo.NetworkController)) {
            $global:SdnDiagnostics.EnvironmentInfo.NetworkController = Get-SdnNetworkController -NetworkController $NetworkController -ServerNameOnly -Credential $Credential
        }

        # get the load balancer muxes
        if ([System.String]::IsNullOrEmpty($global:SdnDiagnostics.EnvironmentInfo.SoftwareLoadBalancer)) {
            $global:SdnDiagnostics.EnvironmentInfo.SoftwareLoadBalancer = Get-SdnLoadBalancerMux -NcUri $Global:SdnDiagnostics.EnvironmentInfo.NcUrl -ManagementAddressOnly -Credential $NcRestCredential
        }

        # get the gateways
        if ([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.EnvironmentInfo.Gateway)) {
            $Global:SdnDiagnostics.EnvironmentInfo.Gateway = Get-SdnGateway -NcUri $Global:SdnDiagnostics.EnvironmentInfo.NcUrl -ManagementAddressOnly -Credential $NcRestCredential
        }

        # get the hypervisor hosts
        if ([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.EnvironmentInfo.Server)) {
            $Global:SdnDiagnostics.EnvironmentInfo.Server = Get-SdnServer -NcUri $Global:SdnDiagnostics.EnvironmentInfo.NcUrl -ManagementAddressOnly -Credential $NcRestCredential
        }

        # populate the global cache that contains the names of the nodes for the roles defined above
        $fabricNodes = @()
        $fabricNodes += $global:SdnDiagnostics.EnvironmentInfo.NetworkController
        $fabricNodes += $Global:SdnDiagnostics.EnvironmentInfo.Server
        $fabricNodes += $Global:SdnDiagnostics.EnvironmentInfo.Gateway
        $fabricNodes += $global:SdnDiagnostics.EnvironmentInfo.SoftwareLoadBalancer

        $Global:SdnDiagnostics.EnvironmentInfo.FabricNodes = $fabricNodes

        return $Global:SdnDiagnostics.EnvironmentInfo
    }
    catch {
        # Remove any cached info in case of exception as the cached info might be incorrect
        $Global:SdnDiagnostics.EnvironmentInfo.NcUrl = $null
        $global:SdnDiagnostics.EnvironmentInfo.NetworkController = $null
        $global:SdnDiagnostics.EnvironmentInfo.SoftwareLoadBalancer = $null
        $Global:SdnDiagnostics.EnvironmentInfo.Gateway = $null
        $Global:SdnDiagnostics.EnvironmentInfo.Server = $null
        $Global:SdnDiagnostics.EnvironmentInfo.FabricNodes = $null
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
