function Get-SdnNetworkControllerFCClusterInfo {
    <#
    .SYNOPSIS
        Gather the Network Controller cluster wide info from one of the Network Controller
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER OutputDirectory
        Directory location to save results. It will create a new sub-folder called NetworkControllerClusterInfo_FC that the files will be saved to
    .EXAMPLE
        PS> Get-SdnNetworkControllerFCClusterInfo
    .EXAMPLE
        PS> Get-SdnNetworkControllerFCClusterInfo -NetworkController 'NC01' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$NetworkController,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    $currentErrorActionPreference = $ErrorActionPreference
    $ProgressPreference = 'SilentlyContinue'
    $ErrorActionPreference = 'Ignore'

    try {
        $outputDir = Join-Path -Path $OutputDirectory.FullName -ChildPath 'NetworkControllerClusterInfo_FC'
        if (!(Test-Path -Path $outputDir -PathType Container)) {
            $null = New-Item -Path $outputDir -ItemType Directory -Force
        }

        $clusterName = $Global:SdnDiagnostics.EnvironmentInfo.FailoverClusterConfig.Name
        if ($null -ieq $clusterName) {
            $clusterName = Get-SdnClusterName -NetworkController $NetworkController -Credential $Credential -ErrorAction Stop
        }

        Get-Cluster -Name $clusterName | Export-ObjectToFile -FilePath $outputDir -Name 'Get-Cluster' -FileType json
        Get-ClusterFaultDomain -CimSession $clusterName | Export-ObjectToFile -FilePath $outputDir -Name 'Get-ClusterFaultDomain' -FileType json
        Get-ClusterNode -Cluster $clusterName | Export-ObjectToFile -FilePath $outputDir -Name 'Get-ClusterNode' -FileType json
        Get-ClusterGroup -Cluster $clusterName | Export-ObjectToFile -FilePath $outputDir -Name 'Get-ClusterGroup' -FileType json
        Get-ClusterNetwork -Cluster $clusterName | Export-ObjectToFile -FilePath $outputDir -Name 'Get-ClusterNetwork' -FileType json
        Get-ClusterNetworkInterface -Cluster $clusterName | Export-ObjectToFile -FilePath $outputDir -Name 'Get-ClusterNetworkInterface' -FileType json
        Get-ClusterResource -Cluster $clusterName | Export-ObjectToFile -FilePath $outputDir -Name 'Get-ClusterResource' -FileType json
        Get-ClusterResourceType -Cluster $clusterName | Export-ObjectToFile -FilePath $outputDir -Name 'Get-ClusterResourceType' -FileType txt -Format Table
        Get-ClusterSharedVolume -Cluster $clusterName | Export-ObjectToFile -FilePath $outputDir -Name 'Get-ClusterSharedVolume' -FileType json
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }

    $ProgressPreference = 'Continue'
    $ErrorActionPreference = $currentErrorActionPreference
}
