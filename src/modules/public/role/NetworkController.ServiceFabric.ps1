function Invoke-SdnServiceFabricCommand {
    <#
    .SYNOPSIS
        Connects to the service fabric ring that is used by Network Controller.
    .PARAMETER ScriptBlock
        A script block containing the service fabric commands to invoke.
    .PARAMETER NetworkController
        Name of the Network Controller to connect to.
    .PARAMETER Credential
        The NC Admin Credential if different from current logon user credential.
    .EXAMPLE
        PS> Invoke-SdnServiceFabricCommand -ScriptBlock { Get-ServiceFabricClusterHealth }    
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [System.String[]]$NetworkController = $Global:SdnDiagnostics.NC,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true)]
        [ScriptBlock]$ScriptBlock
    )

    try {
        if(!$NetworkController){
            "NetworkController is null. Please specify -NetworkController parameter or run Get-SdnInfrastructureInfo to populate the infrastructure cache" | Trace-Output -Level:Warning
            return
        }

        foreach($controller in $NetworkController){
            $session = New-PSRemotingSession -ComputerName $controller -Credential $Credential
            $connection = Invoke-Command -Session $session -HideComputerName -ScriptBlock {
                # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
                Connect-ServiceFabricCluster 3>$null 4>$null
            }

            if($connection){
                "NetworkController: {0}, ScriptBlock: {1}" -f $controller, $ScriptBlock.ToString() | Trace-Output -Level:Verbose
                $sfResults = Invoke-Command -Session $session -ScriptBlock $ScriptBlock
                if($sfResults){
                    break
                }
            }
            else {
                "Unable to execute ServiceFabric commands to {0}" -f $controller | Trace-Output -Level:Error
            }
        }

        if($sfResults) {
            if($sfResults.GetType().IsPrimitive -or ($sfResults -is [String])) {
                return $sfResults
            }
        }
                
        return $sfResults | Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnServiceFabricService {
    <#
    .SYNOPSIS
        Gets service fabric services on the network controller.
    .PARAMETER ApplicationName
        A service fabric application name that exists on the provided ring, such as fabric:/NetworkController.
    .PARAMETER ServiceName
        A service fabric service name that is under the provided ApplicationName on the provided ring, such as fabric:/NetworkController/ApiService.
    .PARAMETER ServiceTypeName
        A service fabric service TypeName, such as VSwitchService
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
        [System.String[]]$NetworkController = $Global:SdnDiagnostics.NC,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )
    
    try {
        switch($PSCmdlet.ParameterSetName){
            'NamedService' {
                $sb = {
                    Get-ServiceFabricApplication -ApplicationName $using:ApplicationName | Get-ServiceFabricService -ServiceName $using:ServiceName
                }
            }

            'NamedServiceTypeName' {
                $sb = {
                    Get-ServiceFabricApplication -ApplicationName $using:ApplicationName | Get-ServiceFabricService -ServiceTypeName $using:ServiceTypeName
                }
            }

            default {
                $sb = {
                    Get-ServiceFabricApplication | Get-ServiceFabricService
                }
            }
        }

        if($NetworkController){
            Invoke-SdnServiceFabricCommand -NetworkController $NetworkController -ScriptBlock $sb -Credential $Credential
        }
        else {
            Invoke-SdnServiceFabricCommand -ScriptBlock $sb -Credential $Credential
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnServiceFabricReplica {
    <#
    .SYNOPSIS
        Gets the replicas for a specified service fabric service.
    .PARAMETER ApplicationName
        A service fabric application name that exists on the provided ring, such as fabric:/NetworkController.
    .PARAMETER ServiceName
        A service fabric service name that is under the provided ApplicationName on the provided ring, such as fabric:/NetworkController/ApiService.
    .PARAMETER ServiceTypeName
        A service fabric service TypeName, such as VSwitchService.
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
        [System.String[]]$NetworkController = $Global:SdnDiagnostics.NC,

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
        switch($PSCmdlet.ParameterSetName){
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

        if($NetworkController){
            $replica = Invoke-SdnServiceFabricCommand -NetworkController $NetworkController -ScriptBlock $sb -Credential $Credential
        }
        else {
            $replica = Invoke-SdnServiceFabricCommand -ScriptBlock $sb -Credential $Credential
        }

        # as network controller only leverages stateful service fabric services, we will have Primary and ActiveSecondary replicas
        # if the -Primary switch was declared, we only want to return the primary replica for that particular service
        if($Primary){
            return ($replica | Where-Object {$_.ReplicaRole -ieq 'Primary'})
        }
        else {
            return $replica
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Move-SdnServiceFabricReplica {
    <#
    .SYNOPSIS
        Moves the primary replica of the provided service to an available node.
    .PARAMETER ApplicationName
        A service fabric application name that exists on the provided ring, such as fabric:/NetworkController.
    .PARAMETER ServiceName
        A service fabric service name that is under the provided ApplicationName on the provided ring, such as fabric:/NetworkController/ApiService.
    .PARAMETER ServiceTypeName
        A service fabric service TypeName, such as VSwitchService.
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
        [System.String[]]$NetworkController = $Global:SdnDiagnostics.NC,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )
    try {
        if($PSCmdlet.ParameterSetName -eq 'NamedService'){
            $sfParams = @{
                ServiceName = $ServiceName
                Credential = $Credential
            }
        }
        elseif($PSCmdlet.ParameterSetName -eq 'NamedServiceTypeName'){
            $sfParams = @{
                ServiceTypeName = $ServiceTypeName
                Credential = $Credential
            }
        }

        # add NetworkController to hash table for splatting if defined
        if($NetworkController){
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
        if($NetworkController){
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