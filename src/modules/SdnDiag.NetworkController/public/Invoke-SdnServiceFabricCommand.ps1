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

    $connectSFCluster = {
        if (( Get-Service -Name 'FabricHostSvc').Status -ine 'Running' ) {
            throw "Service Fabric Service is currently not running."
        }

        # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
        Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null
    }

    $i = 0
    $maxRetry = 3

    $params = @{
        ScriptBlock = $ScriptBlock
    }
    if ($ArgumentList) {
        $params.Add('ArgumentList', $ArgumentList)
    }

    "Invoke Service Fabric cmdlets against {0}" -f $NetworkController | Trace-Output -Level Verbose
    while ($i -lt $maxRetry) {
        $i++

        try {
            if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
                Confirm-IsNetworkController
                $connection = Invoke-Command -ScriptBlock $connectSFCluster -ErrorAction Stop
            }
            else {
                try {
                    $session = New-PSRemotingSession -ComputerName $NetworkController -Credential $Credential -ErrorAction Stop
                    if (-NOT ($params.ContainsKey('Session'))) {
                        $params.Add('Session', $session)
                    }
                    else {
                        $params.Session = $session
                    }

                    $connection = Invoke-Command -Session $session -ScriptBlock $connectSFCluster -ErrorAction Stop
                }
                # due to scenario as described in https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-troubleshoot-local-cluster-setup#cluster-connection-fails-with-object-is-closed
                # we want to catch any exception when connecting to service fabric cluster, and if necassary destroy and create a new remote pssession
                catch [Microsoft.ServiceFabric.Powershell.ConnectCluster+FabricObjectClosedException] {
                    "Terminating remote session {0} to {1}" -f $session.Name, $session.ComputerName | Trace-Output -Level:Warning
                    Get-PSSession -Id $session.Id | Remove-PSSession
                }
                catch {
                    throw $_
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
                    "Unable to connect to Service Fabric Cluster. Attempt {0}/{1}`n`t{2}" -f $i, $maxRetry, $_ | Trace-Output -Level:Error
                }
            }
        }

        if ($connection) {
            break
        }
    }

    # if we were not able to create a connection
    if (!$connection) {
        throw "Unable to connect to Service Fabric Cluster"
    }

    "NetworkController: {0}, ScriptBlock: {1}" -f $NetworkController, $ScriptBlock.ToString() | Trace-Output -Level:Verbose
    if ($params.ArgumentList) {
        "ArgumentList: {0}" -f ($params.ArgumentList | ConvertTo-Json).ToString() | Trace-Output -Level:Verbose
    }

    # if we get results from service fabric, then we want to break out of the loop
    # otherwise we will try again to see if state issue with service fabric or the particular node
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
