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
    .PARAMETER NodeName
        Specifies the name of a Service Fabric node. The cmdlet moves the primary replica to the node that you specify.
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
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String]$NodeName,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sfParams = @{
        Credential  = $Credential
        NetworkController = $NetworkController
    }

    if ($PSCmdlet.ParameterSetName -eq 'NamedService') {
        $getSFParams.Add('ServiceName',$ServiceName)
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'NamedServiceTypeName') {
        $getSFParams.Add('ServiceTypeName',$ServiceTypeName)
    }

    $sfServiceParams = $sfParams

    try {
        # check to determine how many replicas are part of the partition for the service
        # if we only have a single replica, then generate a warning and stop further processing
        # otherwise locate the primary replica
        $service = Get-SdnServiceFabricService @sfServiceParams -ErrorAction Stop
        $serviceFabricReplicas = Get-SdnServiceFabricReplica @sfServiceParams -ErrorAction Stop
        if ($serviceFabricReplicas.Count -lt 3) {
            "Moving Service Fabric replica is only supported when running 3 or more instances of Network Controller" | Trace-Output -Level:Warning
            return
        }

        $replicaBefore = $serviceFabricReplicas | Where-Object {$_.ReplicaRole -ieq 'Primary'}

        # regardless if user defined ServiceName or ServiceTypeName, the $service object returned will include the ServiceName property
        # which we will use to perform the move operation with
        if ($NodeName) {
            $sfParams.Add('ArgumentList',@($service.ServiceName, $NodeName))
            $scriptBlock = {
                param([string]$param1, [string]$param2)
                Move-ServiceFabricPrimaryReplica -ServiceName $param1 -NodeName $param2
            }
        }
        else {
            $sfParams.Add('ArgumentList',@($service.ServiceName))
            $scriptBlock = {
                param([string]$param1)
                Move-ServiceFabricPrimaryReplica -ServiceName $param1
            }
        }

        # no useful information is returned during the move operation, so we will just null the results that are returned back
        $null = Invoke-SdnServiceFabricCommand @sfParams -ScriptBlock $scriptBlock

        # update the hash table to now define -Primary switch, which will be used to get the service fabric replica primary
        [void]$sfServiceParams.Add('Primary', $true)
        $replicaAfter = Get-SdnServiceFabricReplica @sfServiceParams
        "Replica for {0} has been moved from {1} to {2}" -f $service.ServiceName, $replicaBefore.NodeName, $replicaAfter.NodeName | Trace-Output
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
