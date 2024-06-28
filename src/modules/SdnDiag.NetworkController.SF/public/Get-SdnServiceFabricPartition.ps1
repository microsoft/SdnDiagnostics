function Get-SdnServiceFabricPartition {
    <#
    .SYNOPSIS
        Gets information about the partitions of a specified Service Fabric partition or service from Network Controller.
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
        PS> Get-SdnServiceFabricPartition -PartitionId 1a7a780e-dbfe-46d3-92fb-76908a95ce54
    .EXAMPLE
        PS> Get-SdnServiceFabricPartition -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -ServiceTypeName 'ApiService'
    .EXAMPLE
        PS> Get-SdnServiceFabricPartition -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -ServiceName 'fabric:/NetworkController/ApiService'
    #>

    [CmdletBinding(DefaultParameterSetName = 'NamedService')]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String]$ApplicationName = 'fabric:/NetworkController',

        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [System.String]$ServiceName,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String]$ServiceTypeName,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'PartitionID')]
        [System.Guid]$PartitionId,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'PartitionID')]
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'PartitionID')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sfParams = @{
        Credential  = $Credential
        NetworkController = $NetworkController
    }

    switch ($PSCmdlet.ParameterSetName) {
        'NamedService' {
            $sfParams.Add('ArgumentList',@($ApplicationName, $ServiceName))
            $sb = {
                param([string]$param1, [string]$param2)
                # check if service fabric service is running
                $serviceState = Get-Service -Name 'FabricHostSvc' -ErrorAction Stop
                if ($serviceState.Status -ne 'Running') {
                    throw New-Object System.Exception("Service Fabric Service is currently not running.")
                }

                # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
                $null = Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null
                Get-ServiceFabricApplication -ApplicationName $param1 | Get-ServiceFabricService -ServiceName $param2 | Get-ServiceFabricPartition
            }
        }

        'NamedServiceTypeName' {
            $sfParams.Add('ArgumentList',@($ApplicationName, $ServiceTypeName))
            $sb = {
                param([string]$param1, [string]$param2)
                # check if service fabric service is running
                $serviceState = Get-Service -Name 'FabricHostSvc' -ErrorAction Stop
                if ($serviceState.Status -ne 'Running') {
                    throw New-Object System.Exception("Service Fabric Service is currently not running.")
                }

                # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
                $null = Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null
                Get-ServiceFabricApplication -ApplicationName $param1 | Get-ServiceFabricService -ServiceTypeName $param2 | Get-ServiceFabricPartition
            }
        }

        'PartitionID' {
            $sfParams.Add('ArgumentList',@($PartitionId))
            $sb = {
                param([Guid]$param1)
                # check if service fabric service is running
                $serviceState = Get-Service -Name 'FabricHostSvc' -ErrorAction Stop
                if ($serviceState.Status -ne 'Running') {
                    throw New-Object System.Exception("Service Fabric Service is currently not running.")
                }

                # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
                $null = Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null
                Get-ServiceFabricPartition -PartitionId $param1
            }
        }
    }

    try {
        Invoke-SdnServiceFabricCommand @sfParams -ScriptBlock $sb
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
