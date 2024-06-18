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
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [Switch]$Primary
    )

    $sfParams = @{
        NetworkController = $NetworkController
        Credential = $Credential
    }

    switch ($PSCmdlet.ParameterSetName) {
        'NamedService' {
            $sfParams.Add('ArgumentList', @($ApplicationName, $ServiceName))
            $sb = {
                param([string]$param1, [string]$param2)
                # check if service fabric service is running
                $serviceState = Get-Service -Name 'FabricHostSvc' -ErrorAction Stop
                if ($serviceState.Status -ne 'Running') {
                    throw New-Object System.Exception("Service Fabric Service is currently not running.")
                }

                # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
                $null = Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null
                Get-ServiceFabricApplication -ApplicationName $param1 | Get-ServiceFabricService -ServiceName $param2 | Get-ServiceFabricPartition | Get-ServiceFabricReplica
            }
        }

        'NamedServiceTypeName' {
            $sfParams.Add('ArgumentList', @($ApplicationName, $ServiceTypeName))
            $sb = {
                param([string]$param1, [string]$param2)
                # check if service fabric service is running
                $serviceState = Get-Service -Name 'FabricHostSvc' -ErrorAction Stop
                if ($serviceState.Status -ne 'Running') {
                    throw New-Object System.Exception("Service Fabric Service is currently not running.")
                }

                # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
                $null = Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null
                Get-ServiceFabricApplication -ApplicationName $param1 | Get-ServiceFabricService -ServiceTypeName $param2 | Get-ServiceFabricPartition | Get-ServiceFabricReplica
            }
        }
    }

    try {
        $replica = Invoke-SdnServiceFabricCommand @sfParams -ScriptBlock $sb

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
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
