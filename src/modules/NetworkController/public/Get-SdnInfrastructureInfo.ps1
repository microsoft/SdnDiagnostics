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
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    try {

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

        # populate the global cache that contains the names of the nodes for the roles defined above
        $fabricNodes = [System.Collections.ArrayList]::new()
        [void]$fabricNodes.Add($Global:SdnDiagnostics.EnvironmentInfo.NC)
        [void]$fabricNodes.Add($Global:SdnDiagnostics.EnvironmentInfo.Host)
        [void]$fabricNodes.Add($Global:SdnDiagnostics.EnvironmentInfo.Gateway)
        [void]$fabricNodes.Add($Global:SdnDiagnostics.EnvironmentInfo.MUX)
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
