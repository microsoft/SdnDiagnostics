# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnInfrastructureInfo {
    <#
    .SYNOPSIS
        Get the SDN infrastructure information from network controller. The function will update the $Global:SdnDiagnostics.EnvironmentInfo variable.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operates.
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
        [Parameter(Mandatory = $true)]
        [String]$NetworkController,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

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
            $Global:SdnDiagnostics.EnvironmentInfo.NC = $null
            $Global:SdnDiagnostics.EnvironmentInfo.MUX = $null
            $Global:SdnDiagnostics.EnvironmentInfo.Gateway = $null
            $Global:SdnDiagnostics.EnvironmentInfo.Host = $null
            $Global:SdnDiagnostics.EnvironmentInfo.FabricNodes = $null
        }

        # get the NC Northbound API endpoint
        if ([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.EnvironmentInfo.NcUrl)) {
            $result = Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock { Get-NetworkController } -Credential $Credential
            $Global:SdnDiagnostics.EnvironmentInfo.NcUrl = "https://$($result.RestName)"
        }

        # get the network controllers
        if ([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.EnvironmentInfo.NC)) {
            $Global:SdnDiagnostics.EnvironmentInfo.NC = Get-SdnNetworkController -NetworkController $NetworkController -ServerNameOnly -Credential $Credential
        }

        # get the load balancer muxes
        if ([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.EnvironmentInfo.MUX)) {
            $Global:SdnDiagnostics.EnvironmentInfo.MUX = Get-SdnLoadBalancerMux -NcUri $Global:SdnDiagnostics.EnvironmentInfo.NcUrl -ManagementAddressOnly -Credential $NcRestCredential
        }

        # get the gateways
        if ([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.EnvironmentInfo.Gateway)) {
            $Global:SdnDiagnostics.EnvironmentInfo.Gateway = Get-SdnGateway -NcUri $Global:SdnDiagnostics.EnvironmentInfo.NcUrl -ManagementAddressOnly -Credential $NcRestCredential
        }

        # get the hypervisor hosts
        if ([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.EnvironmentInfo.Host)) {
            $Global:SdnDiagnostics.EnvironmentInfo.Host = Get-SdnServer -NcUri $Global:SdnDiagnostics.EnvironmentInfo.NcUrl -ManagementAddressOnly -Credential $NcRestCredential
        }

        # get the supported rest API versions from network controller
        # as we default this to v1 on module import within $Global.SdnDiagnostics, will not check to see if null first
        $Global:SdnDiagnostics.EnvironmentInfo.RestApiVersion = (Get-SdnDiscovery -NcUri $Global:SdnDiagnostics.EnvironmentInfo.NcUrl -Credential $NcRestCredential).properties.currentRestVersion

        # populate the global cache that contains the names of the nodes for the roles defined above
        $fabricNodes = @()
        $fabricNodes += $Global:SdnDiagnostics.EnvironmentInfo.NC
        $fabricNodes += $Global:SdnDiagnostics.EnvironmentInfo.Host
        $fabricNodes += $Global:SdnDiagnostics.EnvironmentInfo.Gateway
        $fabricNodes += $Global:SdnDiagnostics.EnvironmentInfo.MUX

        $Global:SdnDiagnostics.EnvironmentInfo.FabricNodes = $fabricNodes

        return $Global:SdnDiagnostics.EnvironmentInfo
    }
    catch {
        # Remove any cached info in case of exception as the cached info might be incorrect
        $Global:SdnDiagnostics.EnvironmentInfo.NcUrl = $null
        $Global:SdnDiagnostics.EnvironmentInfo.NC = $null
        $Global:SdnDiagnostics.EnvironmentInfo.MUX = $null
        $Global:SdnDiagnostics.EnvironmentInfo.Gateway = $null
        $Global:SdnDiagnostics.EnvironmentInfo.Host = $null
        $Global:SdnDiagnostics.EnvironmentInfo.FabricNodes = $null
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
