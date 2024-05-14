function Test-ServiceFabricClusterHealth {
    <#
    .SYNOPSIS
        Validate the health of the Network Controller cluster within Service Fabric.
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

    try {
        "Validating the Service Fabric Cluster Health for Network Controller" | Trace-Output

        $ncNodes = Get-SdnServiceFabricNode -NetworkController $SdnEnvironmentObject.ComputerName[0] -Credential $credential
        if($null -eq $ncNodes){
            throw New-Object System.NullReferenceException("Unable to retrieve service fabric nodes")
        }

        $clusterHealth = Get-SdnServiceFabricClusterHealth -NetworkController $SdnEnvironmentObject.ComputerName[0] -Credential $Credential
        if ($clusterHealth.AggregatedHealthState -ine 'Ok') {
            $sdnHealthObject.Result = 'FAIL'
            $sdnHealthObject.Remediation += "Examine the Service Fabric Cluster Health for Network Controller to determine why the health is not OK."
        }

        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
