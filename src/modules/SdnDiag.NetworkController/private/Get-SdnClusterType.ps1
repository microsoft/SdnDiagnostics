function Get-SdnClusterType {
    <#
    .SYNOPSIS
        Determines the cluster type of the Network Controller
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnClusterType
    .EXAMPLE
        PS> Get-SdnClusterType -NetworkController 'NC01' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$NetworkController,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sb = {
        try {
            # with failover cluster, the ApiService will run as a service within windows
            # so we can check if the service exists to determine if it is a failover cluster configuration regardless if running
            $service = Get-Service -Name 'ApiService' -ErrorAction Ignore
            if ($service) {
                return 'FailoverCluster'
            }
        }
        catch {
            return 'ServiceFabric'
        }
    }

    if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
        $result = Invoke-Command -ScriptBlock $sb
    }
    else {
        $result = Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock $sb -Credential $Credential
    }

    "Cluster Type: $result" | Trace-Output -Level:Verbose
    return $result
}
