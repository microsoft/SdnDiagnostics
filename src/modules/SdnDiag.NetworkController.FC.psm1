# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Import-Module $PSScriptRoot\SdnDiag.Common.psm1
Import-Module $PSScriptRoot\SdnDiag.Utilities.psm1

# create local variable to store configuration data
$configurationData = Import-PowerShellDataFile -Path $PSScriptRoot\SdnDiag.NetworkController.FC.Config.psd1
New-Variable -Name 'SdnDiagnostics_NC_FC' -Scope 'Script' -Force -Value @{
    Config = $configurationData
}

##########################
#### CLASSES & ENUMS #####
##########################

##########################
#### ARG COMPLETERS ######
##########################

##########################
####### FUNCTIONS ########
##########################

function Get-NetworkControllerFCConfigState {
    <#
    .SYNOPSIS
        Outputs a set of configuration state files for the network controller role.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .EXAMPLE
        PS> Get-NetworkControllerFCConfigState -OutputDirectory "C:\Temp\CSS_SDN"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    $currentErrorActionPreference = $ErrorActionPreference
    $ProgressPreference = 'SilentlyContinue'
    $ErrorActionPreference = 'SilentlyContinue'
    [string]$outDir = Join-Path -Path $OutputDirectory.FullName -ChildPath "ConfigState/NetworkController"

    try {
        $config = Get-SdnModuleConfiguration -Role 'NetworkController_FC'
        "Collect configuration state details for role {0}" -f $config.Name | Trace-Output
        if (-NOT (Initialize-DataCollection -Role $config.Name -FilePath $outDir -MinimumMB 10)) {
            "Unable to initialize environment for data collection for {0}" -f $config.Name | Trace-Output -Level:Error
            return
        }

        [string]$regDir = Join-Path -Path $outDir -ChildPath "Registry"
        Export-RegistryKeyConfigDetails -Path $config.properties.regKeyPaths -OutputDirectory $regDir

        Get-Cluster | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-ClusterFaultDomain | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-ClusterNode | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-ClusterGroup | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-ClusterNetwork | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-ClusterNetworkInterface | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-ClusterResource | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-ClusterResourceType | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-ClusterSharedVolume | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }

    $ProgressPreference = 'Continue'
    $ErrorActionPreference = $currentErrorActionPreference
}

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

function Get-SdnNetworkControllerFC {
    <#
    .SYNOPSIS
        Gets network controller application settings from the network controller node leveraging Failover Cluster.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnNetworkControllerFC
    .EXAMPLE
        PS> Get-SdnNetworkControllerFC -NetworkController 'NC01' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
            Confirm-IsNetworkController
            $result = Get-NetworkControllerOnFailoverCluster
        }
        else {
            $result = Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock { Get-NetworkControllerOnFailoverCluster } -Credential $Credential
        }

        return $result
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

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

        Get-Cluster -Name $clusterName | Export-ObjectToFile -FilePath $outputDir -FileType txt -Format List
        Get-ClusterFaultDomain -CimSession $clusterName | Export-ObjectToFile -FilePath $outputDir -FileType txt -Format List
        Get-ClusterNode -Cluster $clusterName | Export-ObjectToFile -FilePath $outputDir -FileType txt -Format List
        Get-ClusterGroup -Cluster $clusterName | Export-ObjectToFile -FilePath $outputDir -FileType txt -Format List
        Get-ClusterNetwork -Cluster $clusterName | Export-ObjectToFile -FilePath $outputDir -FileType txt -Format List
        Get-ClusterNetworkInterface -Cluster $clusterName | Export-ObjectToFile -FilePath $outputDir -FileType txt -Format List
        Get-ClusterResource -Cluster $clusterName | Export-ObjectToFile -FilePath $outputDir -FileType txt -Format List
        Get-ClusterResourceType -Cluster $clusterName | Export-ObjectToFile -FilePath $outputDir -FileType txt -Format List
        Get-ClusterSharedVolume -Cluster $clusterName | Export-ObjectToFile -FilePath $outputDir -FileType txt -Format List
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }

    $ProgressPreference = 'Continue'
    $ErrorActionPreference = $currentErrorActionPreference
}

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

function Confirm-IsFailoverClusterNC {
    $service = Get-Service -Name 'SDNApiService' -ErrorAction Ignore
    if ($service) {
        return $true
    }

    return $false
}

function Get-SdnClusterLog {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [System.IO.FileInfo]$OutputDirectory = (Get-WorkingDirectory)
    )

    # The 3>$null 4>$null sends warning and error to null
    # typically Get-ClusterLog does not like remote powershell operations and generates warnings/errors
    $clusterLogFiles = Get-ClusterLog -Destination $OutputDirectory.FullName 2>$null 3>$null

    # if we have cluster log files, we will zip them up to preserve disk space
    if ($clusterLogFiles) {
        $clusterLogFiles | ForEach-Object {
            $zipFilePath = Join-Path -Path $OutputDirectory.FullName -ChildPath ($_.Name + ".zip")
            Compress-Archive -Path $_.FullName -DestinationPath $zipFilePath -Force -ErrorAction Stop

            # if the file was successfully zipped, we can remove the original file
            if (Get-Item -Path $zipFilePath -ErrorAction Ignore) {
                Remove-Item -Path $_.FullName -Force -ErrorAction Ignore
            }
        }
    }
}
