function Get-SdnClusterName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$NetworkController,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
        $clusterName = Get-Cluster | Select-Object -ExpandProperty Name
    }
    else {
        if ($null -ieq $Credential -or $Credential -eq [System.Management.Automation.PSCredential]::Empty) {
            $clusterName = Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock { Get-Cluster } | Select-Object -ExpandProperty Name
        }
        else {
            $clusterName = Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock { Get-Cluster } -Credential $Credential | Select-Object -ExpandProperty Name
        }
    }

    "Cluster Name: $clusterName" | Trace-Output -Level:Verbose
    return $clusterName
}
