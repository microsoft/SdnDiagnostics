function Invoke-SdnServiceFabricCommand {
    <#
    .SYNOPSIS
        Connects to the service fabric ring that is used by Network Controller.
    .PARAMETER ScriptBlock
        Specifies the commands to run. Enclose the commands in braces ({ }) to create a script block. When using Invoke-Command to run a command remotely, any variables in the command are evaluated on the remote computer.
    .PARAMETER ArgumentList
        Supplies the values of parameters for the scriptblock. The parameters in the script block are passed by position from the array value supplied to ArgumentList. This is known as array splatting.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Invoke-SdnServiceFabricCommand -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -ScriptBlock { Get-ServiceFabricClusterHealth }
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true)]
        [ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory = $false)]
        [Object[]]$ArgumentList = $null
    )

    $i = 0
    $maxRetry = 2
    $params = @{
        ScriptBlock = $ScriptBlock
    }
    if ($ArgumentList) {
        $params.Add('ArgumentList', $ArgumentList)
    }

    if (-NOT ($PSBoundParameters.ContainsKey('NetworkController'))) {
        $config = Get-SdnModuleConfiguration -Role 'NetworkController'
        $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
        if (-NOT ($confirmFeatures)) {
            "The current machine is not a NetworkController, run this on NetworkController or use -NetworkController parameter to specify one" | Trace-Output -Level:Warning
            return # don't throw exception, since this is a controlled scenario and we do not need stack exception tracing
        }
    }

    "Invoke Service Fabric cmdlet against {0}" -f $NetworkController | Trace-Output -Level Verbose
    while ($i -lt $maxRetry) {
        $i++

        try {
            if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
                $connection = Invoke-Command -ScriptBlock {
                    if ((Get-Service -Name 'FabricHostSvc').Status -ine 'Running' ) {
                        throw "Service Fabric Service is not running on $NetworkController"
                    }

                    # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
                    Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null
                } -ErrorAction Stop
            }
            else {
                $session = New-PSRemotingSession -ComputerName $NetworkController -Credential $Credential
                if (!$session) {
                    throw "Unable to establish a remote session to $NetworkController"
                }
                $connection = Invoke-Command -Session $session -ScriptBlock {
                    if ((Get-Service -Name 'FabricHostSvc').Status -ine 'Running' ) {
                        throw "Service Fabric Service is not running on $NetworkController"
                    }

                    # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
                    Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null
                } -ErrorAction Stop

                if (!$connection) {
                    throw "Unable to connect to Service Fabric Cluster"
                }
            }
        }
        catch {
            switch -Wildcard ($_.Exception.Message) {
                "*Service Fabric Service is not running*" {
                    # Handle the case where the Service Fabric service is not running
                    "Service Fabric Service is not running on $NetworkController" | Trace-Output -Level:Error
                    throw $_
                }
                default {
                    $_ | Trace-Exception
                    "Unable to connect to Service Fabric Cluster. Attempt {0}/{1}" -f $i, $maxRetry | Trace-Output -Level:Error
                }
            }

            # due to scenario as described in https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-troubleshoot-local-cluster-setup#cluster-connection-fails-with-object-is-closed
            # we want to catch any exception when connecting to service fabric cluster, and if necassary destroy and create a new remote pssession
            if ($session) {
                "Terminating remote session {0} to {1}" -f $session.Name, $session.ComputerName | Trace-Output -Level:Verbose
                Get-PSSession -Id $session.Id | Remove-PSSession
            }
        }
    }

    if (!$connection) {
        throw "Unable to create a connection Service Fabric Cluster"
    }

    # if we have the session created, we can then construct the remainder of the parameters for splatting purposes
    # and write some verbose details to the log for tracking purposes
    if ($session) {
        $params.Add('Session', $session)
    }

    "NetworkController: {0}, ScriptBlock: {1}" -f $controller, $ScriptBlock.ToString() | Trace-Output -Level:Verbose
    if ($params.ArgumentList) {
        "ArgumentList: {0}" -f ($params.ArgumentList | ConvertTo-Json).ToString() | Trace-Output -Level:Verbose
    }

    $sfResults = Invoke-Command @params
    if (!$sfResults) {
        throw New-Object System.NullReferenceException("Unable to return results from service fabric")
    }

    if ($sfResults.GetType().IsPrimitive -or ($sfResults -is [String])) {
        return $sfResults
    }
    else {
        return ($sfResults | Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId)
    }
}
