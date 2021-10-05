# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnServiceFabricReplica {
    <#
    .SYNOPSIS
        Gets Service Fabric replicas of a partition from Network Controller.
    .PARAMETER ApplicationName
        A service fabric application name that exists on the provided ring, such as fabric:/NetworkController.
    .PARAMETER ServiceName
        A service fabric service name that is under the provided ApplicationName on the provided ring, such as fabric:/NetworkController/ApiService.
    .PARAMETER ServiceTypeName
        A service fabric service TypeName, such as VSwitchService.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnServiceFabricReplica -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -ServiceTypeName 'ApiService'
    .EXAMPLE
        PS> Get-SdnServiceFabricReplica -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -ServiceName 'fabric:/NetworkController/ApiService'
    #>

    [CmdletBinding(DefaultParameterSetName = 'NamedService')]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String]$ApplicationName = 'fabric:/NetworkController',

        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [System.String]$ServiceName,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String]$ServiceTypeName,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String[]]$NetworkController = $global:SdnDiagnostics.EnvironmentInfo.NetworkController,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [Switch]$Primary
    )

    try {
        switch ($PSCmdlet.ParameterSetName) {
            'NamedService' {
                $sb = {
                    Get-ServiceFabricApplication -ApplicationName $using:ApplicationName | Get-ServiceFabricService -ServiceName $using:ServiceName | Get-ServiceFabricPartition | Get-ServiceFabricReplica
                }
            }

            'NamedServiceTypeName' {
                $sb = {
                    Get-ServiceFabricApplication -ApplicationName $using:ApplicationName | Get-ServiceFabricService -ServiceTypeName $using:ServiceTypeName | Get-ServiceFabricPartition | Get-ServiceFabricReplica
                }
            }

            default {
                # no default
            }
        }

        if ($NetworkController) {
            $replica = Invoke-SdnServiceFabricCommand -NetworkController $NetworkController -ScriptBlock $sb -Credential $Credential
        }
        else {
            $replica = Invoke-SdnServiceFabricCommand -ScriptBlock $sb -Credential $Credential
        }

        # as network controller only leverages stateful service fabric services, we will have Primary and ActiveSecondary replicas
        # if the -Primary switch was declared, we only want to return the primary replica for that particular service
        if ($Primary) {
            return ($replica | Where-Object { $_.ReplicaRole -ieq 'Primary' })
        }
        else {
            return $replica
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
