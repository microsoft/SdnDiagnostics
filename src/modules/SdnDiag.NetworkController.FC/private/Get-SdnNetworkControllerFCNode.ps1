function Get-SdnNetworkControllerFCNode {
    <#
    .SYNOPSIS
        Returns a list of servers from network controller.
    .PARAMETER Name
        Specifies the friendly name of the node for the network controller. If not provided, settings are retrieved for all nodes in the deployment.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnNetworkControllerFCNode
    .EXAMPLE
        PS> Get-SdnNetworkControllerFCNode -NetworkController 'NC01' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$Name,

        [Parameter(Mandatory = $false)]
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [switch]$ServerNameOnly
    )

    $params = @{
        NetworkController = $NetworkController
        Credential = $Credential
    }
    if ($Name) {
        $params.Add('Name', $Name)
    }

    $sb = {
        param([String]$param1)
        # native cmdlet to get network controller node information is case sensitive
        # so we need to get all nodes and then filter based on the name
        $ncNodes = Get-ClusterNode -ErrorAction Stop
        if (![string]::IsNullOrEmpty($param1)) {
            return ($ncNodes | Where-Object {$_.Name -ieq $param1})
        }
        else {
            return $ncNodes
        }
    }

    if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
        Confirm-IsNetworkController
    }

    try {
        if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
            $result = Invoke-Command -ScriptBlock $sb -ArgumentList @($Name) -ErrorAction Stop
        }
        else {
            $result = Invoke-PSRemoteCommand -ComputerName $NetworkController -Credential $Credential -ScriptBlock $sb -ArgumentList @($Name) -ErrorAction Stop
        }

        # in this scenario if the results returned we will parse the objects returned and generate warning to user if cluster node is not up
        foreach($obj in $result){
            if($obj.State -ine 'Up'){
                "{0} is reporting state {1}" -f $obj.Name, $obj.State | Trace-Output -Level:Warning
            }
        }

        if($ServerNameOnly){
            return [System.Array]$result.Name
        }
        else {
            return $result
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
