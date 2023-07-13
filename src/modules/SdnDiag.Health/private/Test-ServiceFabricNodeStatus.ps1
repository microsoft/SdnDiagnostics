function Test-ServiceFabricNodeStatus {
    <#
    .SYNOPSIS
        Validate the health of the Network Controller nodes within Service Fabric.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()
    $array = @()

    try {
        "Validating the Service Fabric Nodes for Network Controller" | Trace-Output

        $ncNodes = Get-SdnServiceFabricNode -NetworkController $SdnEnvironmentObject.ComputerName -Credential $credential
        if($null -eq $ncNodes){
            throw New-Object System.NullReferenceException("Unable to retrieve service fabric nodes")
        }

        foreach ($node in $ncNodes) {
            if ($node.NodeStatus -ine 'Up') {
                $sdnHealthObject.Result = 'FAIL'
                $sdnHealthObject.Remediation = 'Fix the Service Fabric Cluster'
            }
        }

        return $sdnHealthObject
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
