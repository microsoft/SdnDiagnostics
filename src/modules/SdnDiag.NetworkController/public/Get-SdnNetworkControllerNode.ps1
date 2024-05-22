function Get-SdnNetworkControllerNode {
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
        PS> Get-SdnNetworkControllerNode
    .EXAMPLE
        PS> Get-SdnNetworkControllerNode -NetworkController 'NC01' -Credential (Get-Credential)
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
        # check if service fabric service is running otherwise this command will hang
        if ((Get-Service -Name 'FabricHostSvc').Status -ine 'Running' ) {
            throw "FabricHostSvc is not running."
        }

        # native cmdlet to get network controller node information is case sensitive
        # so we need to get all nodes and then filter based on the name
        $ncNodes = Get-NetworkControllerNode
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
        try {
            if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
                $result = Invoke-Command -ScriptBlock $sb -ArgumentList @($Name) -ErrorAction Stop
            }
            else {
                $result = Invoke-PSRemoteCommand -ComputerName $NetworkController -Credential $Credential -ScriptBlock $sb -ArgumentList @($Name) -ErrorAction Stop
            }

            # in this scenario if the results returned we will parse the objects returned and generate warning to user if node is not up
            # this property is only going to exist though if service fabric is healthy and underlying NC cmdlet can query node status
            foreach($obj in $result){
                if($obj.Status -ine 'Up'){
                    "{0} is reporting status {1}" -f $obj.Name, $obj.Status | Trace-Output -Level:Warning
                }

                # if we returned the object, we want to add a new property called NodeCertificateThumbprint as this will ensure consistent
                # output in scenarios where this operation fails due to NC unhealthy and we need to fallback to reading the cluster manifest
                $result | ForEach-Object {
                    if (!($_.PSOBject.Properties.name -contains "NodeCertificateThumbprint")) {
                        $_ | Add-Member -MemberType NoteProperty -Name 'NodeCertificateThumbprint' -Value $_.NodeCertificate.Thumbprint
                    }
                }
            }
        }
        catch {
            "Get-NetworkControllerNode failed: {0}" -f $_.Exception.Message | Trace-Output -Level:Error
            $result = Get-NetworkControllerNodeInfoFromClusterManifest @params
        }

        if($ServerNameOnly){
            return [System.Array]$result.Server
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
