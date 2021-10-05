# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Move-SdnServiceFabricReplica {
    <#
    .SYNOPSIS
        Moves the Service Fabric primary replica of a stateful service partition on Network Controller.
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
        PS > Move-SdnServiceFabricReplica -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -ServiceTypeName 'ApiService'
    #>

    [CmdletBinding(DefaultParameterSetName = 'NamedService')]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [String]$ApplicationName = 'fabric:/NetworkController',

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [String]$ServiceName,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [String]$ServiceTypeName,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String[]]$NetworkController = $global:SdnDiagnostics.EnvironmentInfo.NetworkController,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )
    try {
        if ($PSCmdlet.ParameterSetName -eq 'NamedService') {
            $sfParams = @{
                ServiceName = $ServiceName
                Credential  = $Credential
            }
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'NamedServiceTypeName') {
            $sfParams = @{
                ServiceTypeName = $ServiceTypeName
                Credential      = $Credential
            }
        }

        # add NetworkController to hash table for splatting if defined
        if ($NetworkController) {
            [void]$sfParams.Add('NetworkController', $NetworkController)
        }

        $service = Get-SdnServiceFabricService @sfParams

        # update the hash table to now define -Primary switch, which will be used to get the service fabric replica details
        # this is so we can provide information on-screen to the operator to inform them of the primary replica move
        [void]$sfParams.Add('Primary', $true)
        $replicaBefore = Get-SdnServiceFabricReplica @sfParams

        # regardless if user defined ServiceName or ServiceTypeName, the $service object returned will include the ServiceName property
        # which we will use to perform the move operation with
        $sb = {
            Move-ServiceFabricPrimaryReplica -ServiceName $using:service.ServiceName
        }

        # no useful information is returned during the move operation, so we will just null the results that are returned back
        if ($NetworkController) {
            $null = Invoke-SdnServiceFabricCommand -NetworkController $NetworkController -ScriptBlock $sb -Credential $Credential
        }
        else {
            $null = Invoke-SdnServiceFabricCommand -ScriptBlock $sb -Credential $Credential
        }

        $replicaAfter = Get-SdnServiceFabricReplica @sfParams
        "Replica for {0} has been moved from {1} to {2}" -f $service.ServiceName, $replicaBefore.NodeName, $replicaAfter.NodeName | Trace-Output
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
