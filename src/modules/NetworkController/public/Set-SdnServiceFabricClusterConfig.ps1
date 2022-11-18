# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Set-SdnServiceFabricClusterConfig {
    <#
    .SYNOPSIS
        Gets Service Fabric Cluster Config Properties.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates. Default to local machine.
    .PARAMETER Uri
        The Uri to read properties from fabric:/NetworkController/ClusterConfiguration, fabric:/NetworkController/GlobalConfiguration
    .PARAMETER Name
        Property Name to filter the result. If not specified, it will return all properties.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Set-SdnServiceFabricClusterConfig -NetworkController 'NC01' -Uri "fabric:/NetworkController/ClusterConfiguration" -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]$NetworkController = $(HostName),

        [Parameter(Mandatory = $true)]
        [String]$Uri,

        [Parameter(Mandatory = $true)]
        [String]$Name,

        [Parameter(Mandatory = $true)]
        [System.Object]$Value,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty        
    )

    try {
        Connect-ServiceFabricCluster | Out-Null
        $client = [System.Fabric.FabricClient]::new()
        $task = $client.PropertyManager.PutPropertyAsync($Uri, $Name, $Value)
        $task.Wait()
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
