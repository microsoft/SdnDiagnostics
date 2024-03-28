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
        [System.String[]]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true)]
        [ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory = $false)]
        [Object[]]$ArgumentList = $null
    )

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

    foreach ($controller in $NetworkController) {

        $i = 0
        $maxRetry = 3

        # due to scenario as described in https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-troubleshoot-local-cluster-setup#cluster-connection-fails-with-object-is-closed
        # we want to catch any exception when connecting to service fabric cluster, and if necassary destroy and create a new remote pssession
        "Invoke Service Fabric cmdlets against {0}" -f $controller | Trace-Output -Level Verbose
        while ($i -lt $maxRetry) {
            $i++

            $session = New-PSRemotingSession -ComputerName $controller -Credential $Credential
            if (!$session) {
                "No session could be established to {0}" -f $controller | Trace-Output -Level:Error
                break
            }

            try {
                $connection = Invoke-Command -Session $session -ScriptBlock {
                    # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
                    Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null
                } -ErrorAction Stop
            }
            catch {
                "Unable to connect to Service Fabric Cluster. Attempt {0}/{1}`n`t{2}" -f $i, $maxRetry, $_ | Trace-Output -Level:Error
                "Terminating remote session {0} to {1}" -f $session.Name, $session.ComputerName | Trace-Output -Level:Verbose
                Get-PSSession -Id $session.Id | Remove-PSSession
            }
        }

        # if we were not able to create a connection
        # we want to continue the foreach statement to connect to another network controller node (if provided)
        if (!$connection) {
            "Unable to connect to Service Fabric Cluster" | Trace-Output -Level:Error
            continue
        }

        # if we have the session created, we can then construct the remainder of the parameters for splatting purposes
        # and write some verbose details to the log for tracking purposes
        if ($session) {
            if (-NOT ($params.ContainsKey('Session'))) {
                $params.Add('Session', $session)
            }
            else {
                $params.Session = $session
            }

            "NetworkController: {0}, ScriptBlock: {1}" -f $controller, $ScriptBlock.ToString() | Trace-Output -Level:Verbose
            if ($params.ArgumentList) {
                "ArgumentList: {0}" -f ($params.ArgumentList | ConvertTo-Json).ToString() | Trace-Output -Level:Verbose
            }

            # if we get results from service fabric, then we want to break out of the loop
            # otherwise we will try again to see if state issue with service fabric or the particular node
            $sfResults = Invoke-Command @params
            if ($sfResults) {
                break
            }
        }
    }

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
