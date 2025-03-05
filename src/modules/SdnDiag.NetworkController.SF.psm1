# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Import-Module $PSScriptRoot\SdnDiag.Common.psm1
Import-Module $PSScriptRoot\SdnDiag.Utilities.psm1

# create local variable to store configuration data
$configurationData = Import-PowerShellDataFile -Path $PSScriptRoot\SdnDiag.NetworkController.SF.Config.psd1
New-Variable -Name 'SdnDiagnostics_NC_SF' -Scope 'Script' -Force -Value @{
    Config = $configurationData
}

##########################
#### CLASSES & ENUMS #####
##########################

##########################
#### ARG COMPLETERS ######
##########################

$argScriptBlock = @{
    ServiceFabricServiceName = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $serviceName = @(
            'fabric:/NetworkController/ApiService'
            'fabric:/NetworkController/BackupRestore'
            'fabric:/NetworkController/ControllerService'
            'fabric:/NetworkController/FirewallService'
            'fabric:/NetworkController/FnmService'
            'fabric:/NetworkController/GatewayManager'
            'fabric:/NetworkController/HelperService'
            'fabric:/NetworkController/ServiceInsertion'
            'fabric:/NetworkController/SlbManagerService'
            'fabric:/NetworkController/UpdateService'
            'fabric:/NetworkController/VSwitchService'
        )

        if ([string]::IsNullOrEmpty($wordToComplete)) {
            return ($serviceName | Sort-Object)
        }

        return $serviceName | Where-Object {$_ -ilike "*$wordToComplete*"} | Sort-Object
    }

    ServiceFabricServiceTypeName = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $serviceTypeName = @(
            'ApiService'
            'BackupRestore'
            'ControllerService'
            'FirewallService'
            'FnmService'
            'GatewayManager'
            'HelperService'
            'ServiceInsertion'
            'SlbManagerService'
            'UpdateService'
            'VSwitchService'
        )

        if ([string]::IsNullOrEmpty($wordToComplete)) {
            return ($serviceTypeName | Sort-Object)
        }

        return $serviceTypeName | Where-Object {$_ -ilike "*$wordToComplete*"} | Sort-Object
    }
}

Register-ArgumentCompleter -CommandName 'Get-SdnServiceFabricReplica' -ParameterName 'ServiceName' -ScriptBlock $argScriptBlock.ServiceFabricServiceName
Register-ArgumentCompleter -CommandName 'Get-SdnServiceFabricReplica' -ParameterName 'ServiceTypeName' -ScriptBlock $argScriptBlock.ServiceFabricServiceTypeName
Register-ArgumentCompleter -CommandName 'Get-SdnServiceFabricService' -ParameterName 'ServiceName' -ScriptBlock $argScriptBlock.ServiceFabricServiceName
Register-ArgumentCompleter -CommandName 'Get-SdnServiceFabricService' -ParameterName 'ServiceTypeName' -ScriptBlock $argScriptBlock.ServiceFabricServiceTypeName
Register-ArgumentCompleter -CommandName 'Get-SdnServiceFabricPartition' -ParameterName 'ServiceName' -ScriptBlock $argScriptBlock.ServiceFabricServiceName
Register-ArgumentCompleter -CommandName 'Get-SdnServiceFabricPartition' -ParameterName 'ServiceTypeName' -ScriptBlock $argScriptBlock.ServiceFabricServiceTypeName
Register-ArgumentCompleter -CommandName 'Move-SdnServiceFabricReplica' -ParameterName 'ServiceName' -ScriptBlock $argScriptBlock.ServiceFabricServiceName
Register-ArgumentCompleter -CommandName 'Move-SdnServiceFabricReplica' -ParameterName 'ServiceTypeName' -ScriptBlock $argScriptBlock.ServiceFabricServiceTypeName

##########################
####### FUNCTIONS ########
##########################

function Copy-ServiceFabricManifestFromNetworkController {
    <#
    .SYNOPSIS
        Copy the Service Fabric Manifest Files from Network Controller.
    .PARAMETER NcNodeList
        The NcNodeList that retrieved via Get-SdnNetworkControllerInfoOffline.
    .PARAMETER ManifestFolder
        The Manifest Folder path for Manifest files copy to.
    .PARAMETER ManifestFolderNew
        The New Manifest Folder path for updated Manifest files.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $NcNodeList,
        [Parameter(Mandatory = $true)]
        [String]
        $ManifestFolder,
        [Parameter(Mandatory = $true)]
        [String]
        $ManifestFolderNew,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if ($NcNodeList.Count -eq 0) {
            Trace-Output -Message "No NC Node found" -Level:Error
            return
        }
        Trace-Output -Message "Copying Manifest files from $($NcNodeList.IpAddressOrFQDN)" -Level:Verbose

        New-Item -Path $ManifestFolder -ItemType Directory -Force | Out-Null
        New-Item -Path $ManifestFolderNew -ItemType Directory -Force | Out-Null

        $fabricFolder = "$env:ProgramData\Microsoft\Service Fabric\$($NcNodeList[0].NodeName)\Fabric"
        Copy-FileFromRemoteComputer -Path "$fabricFolder\ClusterManifest.current.xml" -ComputerName $($NcNodeList[0].IpAddressOrFQDN) -Destination $ManifestFolder -Credential $Credential
        Copy-FileFromRemoteComputer -Path "$fabricFolder\Fabric.Data\InfrastructureManifest.xml" -ComputerName $($NcNodeList[0].IpAddressOrFQDN) -Destination $ManifestFolder -Credential $Credential

        $NcNodeList | ForEach-Object {
            $fabricFolder = "$env:ProgramData\Microsoft\Service Fabric\$($_.NodeName)\Fabric"

            $version = Invoke-PSRemoteCommand -ComputerName $_.IpAddressOrFQDN -Credential $Credential -ScriptBlock {
                param([Parameter(Position = 0)][String]$param1)
                $fabricPkgFile = Join-Path -Path $param1 -ChildPath "Fabric.Package.current.xml"
                $xml = [xml](Get-Content -Path $fabricPkgFile)
                $version = $xml.ServicePackage.DigestedConfigPackage.ConfigPackage.Version
                return $version
            } -ArgumentList $fabricFolder

            $fabricConfigDir = Join-Path -Path $fabricFolder -ChildPath $("Fabric.Config." + $version)
            $settingsFile = Join-Path -Path $fabricConfigDir -ChildPath "Settings.xml"
            New-Item -Path "$ManifestFolder\$($_.IpAddressOrFQDN)" -type Directory -Force | Out-Null
            New-Item -Path "$ManifestFolderNew\$($_.IpAddressOrFQDN)" -type Directory -Force | Out-Null

            Copy-FileFromRemoteComputer -Path $settingsFile -ComputerName $_.IpAddressOrFQDN -Destination "$ManifestFolder\$($_.IpAddressOrFQDN)" -Credential $Credential
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Copy-ServiceFabricManifestToNetworkController {
    <#
    .SYNOPSIS
        Copy the Service Fabric Manifest Files to Network Controller.
    .PARAMETER NcNodeList
        The NcNodeList that retrieved via Get-SdnNetworkControllerInfoOffline.
    .PARAMETER ManifestFolder
        The Manifest Folder path for Manifest files copy from.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $NcNodeList,
        [Parameter(Mandatory = $true)]
        [String]
        $ManifestFolder,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $stopServiceFabricSB = {
        Stop-Service -Name 'FabricHostSvc' -Force -ErrorAction Ignore 3>$null # redirect warning to null
        if ((Get-Service -Name 'FabricHostSvc' -ErrorAction Ignore).Status -eq 'Stopped') {
            return $true
        }
        else {
            return $false
        }
    }

    try {
        if ($NcNodeList.Count -eq 0) {
            Trace-Output -Message "No NC VMs found" -Level:Error
            return
        }

        # stop service fabric service
        Trace-Output -Message "Stopping Service Fabric Service"
        $stopSfService = Invoke-PSRemoteCommand -ComputerName $NcNodeList.IpAddressOrFQDN -Credential $Credential -ScriptBlock $stopServiceFabricSB `
        -AsJob -PassThru -Activity 'Stopping Service Fabric Service on Network Controller' -ExecutionTimeOut 900

        # enumerate the results of stopping service fabric service
        # if any of the service fabric service is not stopped, throw an exception as we do not want to proceed further
        $stopSfService | ForEach-Object {
            if ($_) {
                "Service Fabric Service stopped on {0}" -f $_.PSComputerName | Trace-Output
            }
            else {
                throw "Failed to stop Service Fabric Service on $($_.PSComputerName)"
            }
        }

        Trace-Output -Message "Copying Service Fabric Manifests to NC VMs: $($NcNodeList.IpAddressOrFQDN)"
        $NcNodeList | ForEach-Object {
            $fabricFolder = "$env:ProgramData\Microsoft\Service Fabric\$($_.NodeName)\Fabric"

            $version = Invoke-PSRemoteCommand -ComputerName $_.IpAddressOrFQDN -Credential $Credential -ScriptBlock {
                param([Parameter(Position = 0)][String]$param1)
                $fabricPkgFile = Join-Path -Path $param1 -ChildPath "Fabric.Package.current.xml"
                $xml = [xml](Get-Content -Path $fabricPkgFile)
                $version = $xml.ServicePackage.DigestedConfigPackage.ConfigPackage.Version
                return $version
            } -ArgumentList $fabricFolder

            $fabricConfigDir = Join-Path -Path $fabricFolder -ChildPath $("Fabric.Config." + $version)
            $settingsFile = Join-Path -Path $fabricConfigDir -ChildPath "Settings.xml"

            Invoke-PSRemoteCommand -ComputerName $_.IpAddressOrFQDN -Credential $Credential -ScriptBlock {
                param([Parameter(Position = 0)][String]$param1, [Parameter(Position = 1)][String]$param2)
                Set-ItemProperty -Path (Join-Path -Path $param1 -ChildPath "ClusterManifest.current.xml") -Name IsReadOnly -Value $false | Out-Null
                Set-ItemProperty -Path (Join-Path -Path $param1 -ChildPath "Fabric.Data\InfrastructureManifest.xml") -Name IsReadOnly -Value $false | Out-Null
                Set-ItemProperty -Path $param2 -Name IsReadOnly -Value $false | Out-Null
            } -ArgumentList @($fabricFolder, $settingsFile)

            Copy-FileToRemoteComputer -Path "$ManifestFolder\ClusterManifest.current.xml" -Destination "$fabricFolder\ClusterManifest.current.xml" -ComputerName $_.IpAddressOrFQDN -Credential $Credential
            Copy-FileToRemoteComputer -Path "$ManifestFolder\InfrastructureManifest.xml" -Destination "$fabricFolder\Fabric.Data\InfrastructureManifest.xml" -ComputerName $_.IpAddressOrFQDN -Credential $Credential
            Copy-FileToRemoteComputer -Path "$ManifestFolder\$($_.IpAddressOrFQDN)\settings.xml" -Destination $settingsFile -ComputerName $_.IpAddressOrFQDN -Credential $Credential
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}


function Get-NetworkControllerNodeInfoFromClusterManifest {
    <#
    .SYNOPSIS
        This function is used as fallback method in the event that normal Get-NetworkControllerNode cmdlet fails in scenarios where certs may be expired
    .PARAMETER NetworkController
        Specifies the Network Controller to retrieve the information from.
    .PARAMETER Name
        Specifies the friendly name of the node for the network controller. If not provided, settings are retrieved for all nodes in the deployment.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]$NetworkController = $(HostName),

        [Parameter(Mandatory = $false)]
        [String]$Name,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    "Attempting to retrieve NetworkControllerNode information via ClusterManifest" | Trace-Output
    $array = @()

    $clusterManifest = [xml](Get-SdnServiceFabricClusterManifest -NetworkController $NetworkController -Credential $Credential)
    $clusterManifest.ClusterManifest.Infrastructure.WindowsServer.NodeList.Node | ForEach-Object {
        $object = [PSCustomObject]@{
            Name = $_.NodeName
            Server = $_.IPAddressOrFQDN
            FaultDomain = $_.FaultDomain
            RestInterface = $null
            Status = $null
            NodeCertificate = $null
        }

	    $certificate = ($clusterManifest.ClusterManifest.NodeTypes.NodeType | Where-Object Name -ieq $_.NodeName).Certificates.ServerCertificate.X509FindValue.ToString()
        $object | Add-Member -MemberType NoteProperty -Name NodeCertificateThumbprint -Value $certificate

        $array += $object
    }

    if ($Name) {
        return ($array | Where-Object { $_.Name.Split(".")[0] -ieq $Name.Split(".")[0] -or $_.Server -ieq $Name.Split(".")[0] })
    }

    return $array
}

function Get-NetworkControllerSFConfigState {
    <#
    .SYNOPSIS
        Outputs a set of configuration state files for the network controller role.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .EXAMPLE
        PS> Get-NetworkControllerSFConfigState -OutputDirectory "C:\Temp\CSS_SDN"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    $currentErrorActionPreference = $ErrorActionPreference
    $ProgressPreference = 'SilentlyContinue'
    $ErrorActionPreference = 'SilentlyContinue'

    try {
        $config = Get-SdnModuleConfiguration -Role 'NetworkController_SF'
        [string]$outDir = Join-Path -Path $OutputDirectory.FullName -ChildPath "ConfigState\NetworkController"

        "Collect configuration state details for role {0}" -f $config.Name | Trace-Output
        if (-NOT (Initialize-DataCollection -Role $config.Name -FilePath $outDir -MinimumMB 20)) {
            "Unable to initialize environment for data collection for {0}" -f $config.Name | Trace-Output -Level:Error
            return
        }

        # enumerate data related to network controller
        Get-SdnNetworkController | Export-ObjectToFile -FilePath $outDir -FileType txt
        Get-SdnNetworkControllerNode | Export-ObjectToFile -FilePath $outDir -FileType txt
        Get-NetworkControllerCluster | Export-ObjectToFile -FilePath $outDir -FileType txt

        # enumerate data related to service fabric
        Get-SdnServiceFabricClusterConfig -Uri ClusterConfiguration | Export-ObjectToFile -FilePath $outDir -FileType txt
        Get-SdnServiceFabricClusterConfig -Uri GlobalConfiguration | Export-ObjectToFile -FilePath $outDir -FileType txt
        Get-SdnServiceFabricClusterHealth | Export-ObjectToFile -FilePath $outDir -FileType txt
        Get-SdnServiceFabricClusterManifest | Out-File -FilePath "$outDir\Get-SdnServiceFabricClusterManifest.xml"

        Get-SdnServiceFabricApplication | Export-ObjectToFile -FilePath $outDir -FileType txt
        Get-SdnServiceFabricApplicationHealth | Export-ObjectToFile -FilePath $outDir -FileType txt

        $ncServices = Get-SdnServiceFabricService
        $ncServices | Export-ObjectToFile -Name 'Get-SdnServiceFabricService' -FilePath $outDir -FileType txt
        foreach ($service in $ncServices) {
            Get-SdnServiceFabricReplica -ServiceName $service.ServiceName | Export-ObjectToFile -FilePath $outDir -FileType txt
        }
        Get-SdnServiceFabricNode | Export-ObjectToFile -FilePath $outDir -FileType txt
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }

    $ProgressPreference = 'Continue'
    $ErrorActionPreference = $currentErrorActionPreference
}

function Get-SdnNetworkControllerInfoFromClusterManifest {
    <#
    .SYNOPSIS
        Get the Network Controller Configuration from network controller cluster manifest file. The function is used to retrieve information of the network controller when cluster down.
    .PARAMETER NetworkController
        Specifies the name the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    "Attempting to retrieve NetworkController information via ClusterManifest" | Trace-Output

    $clusterManifestXml = [xml](Get-SdnServiceFabricClusterManifest -NetworkController $NetworkController -Credential $Credential)
    $nodeList = $clusterManifestXml.ClusterManifest.Infrastructure.WindowsServer.NodeList.Node.NodeName
    $secretCertThumbprint = $clusterManifestXml.ClusterManifest.Certificates.SecretsCertificate.X509FindValue

    $splat = @{
        Path = 'Cert:\LocalMachine\My'
        Thumbprint = $secretCertThumbprint
    }

    if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
        $serverCertificate = Get-SdnCertificate @splat
    }
    else {
        $serverCertificate = Invoke-PSRemoteCommand -ComputerName $NetworkController -Credential $Credential -ScriptBlock {
            param([Parameter(Position = 0)][String]$param1, [Parameter(Position = 1)][String]$param2)
            Get-SdnCertificate -Path $param1 -Thumbprint $param2
        } -ArgumentList @($splat.Path, $splat.Thumbprint)
    }

    $infraInfo = [PSCustomObject]@{
        Node = $nodeList
        ClientAuthentication = $null
        ClientCertificateThumbprint = $null
        ClientSecurityGroup = $null
        ServerCertificate = $serverCertificate
        RestIPAddress = $null
        RestName = $null
        Version = $null
    }

    return $infraInfo
}

function Get-SdnNetworkControllerInfoOffline {
    <#
    .SYNOPSIS
        Get the Network Controller Configuration from network controller cluster manifest file. The function is used to retrieve information of the network controller when cluster down.
    .PARAMETER NetworkController
        Specifies the name the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnNetworkControllerInfoOffline
    .EXAMPLE
        PS> Get-SdnNetworkControllerInfoOffline -NetworkController 'NC01' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
        Confirm-IsNetworkController
    }

    try {
        $clusterManifestXml = [xml](Get-SdnServiceFabricClusterManifest -NetworkController $NetworkController -Credential $Credential)
        $NodeList = $clusterManifestXml.ClusterManifest.Infrastructure.WindowsServer.NodeList.Node
        $securitySection = $clusterManifestXml.ClusterManifest.FabricSettings.Section | Where-Object Name -eq "Security"
        $ClusterCredentialType = $securitySection.Parameter | Where-Object Name -eq "ClusterCredentialType"
        $secretCertThumbprint = $clusterManifestXml.ClusterManifest.Certificates.SecretsCertificate.X509FindValue

        $ncRestName = Invoke-PSRemoteCommand -ComputerName $NetworkController -Credential $Credential -ScriptBlock {
            param([Parameter(Position = 0)][String]$param1, [Parameter(Position = 1)][String]$param2)
            $secretCert = Get-ChildItem -Path $param1 | Where-Object {$_.Thumbprint -ieq $param2}
            if($null -eq $secretCert) {
                return $null
            }
            else {
                return $secretCert.Subject.Replace("CN=","")
            }
        } -ArgumentList @('Cert:\LocalMachine\My', $secretCertThumbprint)

        $infraInfo = [PSCustomObject]@{
            ClusterCredentialType = $ClusterCredentialType.Value
            NodeList = $NodeList
            NcRestName = $ncRestName
            NcRestCertThumbprint = $secretCertThumbprint
        }

        return $infraInfo
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnNetworkControllerSF {
    <#
    .SYNOPSIS
        Gets network controller application settings from the network controller node leveraging Service Fabric.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnNetworkControllerSF
    .EXAMPLE
        PS> Get-SdnNetworkControllerSF -NetworkController 'NC01' -Credential (Get-Credential)
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

    $networkControllerSB = {
        # check if service fabric service is running
        $serviceState = Get-Service -Name 'FabricHostSvc' -ErrorAction Stop
        if ($serviceState.Status -ne 'Running') {
            throw New-Object System.Exception("Service Fabric Service is currently not running.")
        }

        Get-NetworkController
    }

    try {
        try {
            if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
                Confirm-IsNetworkController
                $result = Invoke-Command -ScriptBlock $networkControllerSB -ErrorAction Stop
            }
            else {
                $result = Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock $networkControllerSB -Credential $Credential -ErrorAction Stop
            }
        }
        catch {
            $_ | Trace-Exception
            "Get-NetworkController failed: {0}" -f $_.Exception.Message | Trace-Output -Level:Warning
            $result = Get-SdnNetworkControllerInfoFromClusterManifest -NetworkController $NetworkController -Credential $Credential
        }

        return $result
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnNetworkControllerSFClusterInfo {
    <#
    .SYNOPSIS
        Gather the Network Controller cluster wide info from one of the Network Controller
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER OutputDirectory
        Directory location to save results. It will create a new sub-folder called NetworkControllerClusterInfo_SF that the files will be saved to
    .EXAMPLE
        PS> Get-SdnNetworkControllerSFClusterInfo
    .EXAMPLE
        PS> Get-SdnNetworkControllerSFClusterInfo -NetworkController 'NC01' -Credential (Get-Credential)
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

    try {
        [System.IO.FileInfo]$outputDir = Join-Path -Path $OutputDirectory.FullName -ChildPath 'NetworkControllerClusterInfo_SF'

        if (!(Test-Path -Path $outputDir.FullName -PathType Container)) {
            $null = New-Item -Path $outputDir.FullName -ItemType Directory -Force
        }

        Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock { Get-NetworkController } -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-NetworkController" -FileType txt

        Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock { Get-NetworkControllerNode } -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-NetworkControllerNode" -FileType txt

        Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock { Get-NetworkControllerCluster } -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-NetworkControllerCluster" -FileType txt

        Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock { Get-NetworkControllerReplica } -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-NetworkControllerReplica" -FileType txt

        Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock {  Get-SdnServiceFabricClusterConfig -Uri GlobalConfiguration} -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "NetworkControllerGlobalConfiguration" -FileType txt -Format List

        Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock {  Get-SdnServiceFabricClusterConfig -Uri ClusterConfiguration} -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "NetworkControllerClusterConfiguration" -FileType txt -Format List

        Get-SdnServiceFabricClusterHealth -NetworkController $NetworkController -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-SdnServiceFabricClusterHealth" -FileType txt

        Get-SdnServiceFabricApplicationHealth -NetworkController $NetworkController -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-SdnServiceFabricApplicationHealth" -FileType txt

        Get-SdnServiceFabricClusterManifest -NetworkController $NetworkController -Credential $Credential `
        | Out-File -FilePath "$($outputDir.FullName)\Get-SdnServiceFabricClusterManifest.xml"

        $ncServices = Get-SdnServiceFabricService -NetworkController $NetworkController -Credential $Credential
        $ncServices | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-SdnServiceFabricService" -FileType txt
        foreach ($service in $ncServices) {
            Get-SdnServiceFabricReplica -NetworkController $NetworkController -Credential $Credential -ServiceName $service.ServiceName `
            | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-SdnServiceFabricReplica_$($service.ServiceTypeName)" -FileType txt
        }

        Get-SdnServiceFabricApplication -NetworkController $NetworkController -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-SdnServiceFabricApplication" -FileType txt -Format List

        Get-SdnServiceFabricNode -NetworkController $NetworkController -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-SdnServiceFabricNode" -FileType txt

    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnNetworkControllerSFNode {
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
        PS> Get-SdnNetworkControllerSFNode
    .EXAMPLE
        PS> Get-SdnNetworkControllerSFNode -NetworkController 'NC01' -Credential (Get-Credential)
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
        # check if service fabric service is running
        $serviceState = Get-Service -Name 'FabricHostSvc' -ErrorAction Stop
        if ($serviceState.Status -ne 'Running') {
            throw New-Object System.Exception("Service Fabric Service is currently not running.")
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
            $_ | Trace-Exception
            "Get-NetworkControllerNode failed: {0}" -f $_.Exception.Message | Trace-Output -Level:Warning
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


function Invoke-CertRotateCommand {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Set-NetworkController', 'Set-NetworkControllerCluster', 'Set-NetworkControllerNode')]
        [System.String]$Command,

        [Parameter(Mandatory = $false)]
        [System.String]$Name,

        [Parameter(Mandatory = $false)]
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true)]
        [System.String]$Thumbprint,

        [Parameter(Mandatory = $false)]
        [Int]$TimeoutInMinutes = 30,

        [Parameter(Mandatory = $false)]
        [Int]$MaxRetry = 3
    )

    if ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType -ine 'ServiceFabric') {
        throw New-Object System.NotSupportedException("This function is only supported on Service Fabric clusters.")
    }

    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
    $retryAttempt = 0

    $params = @{
        'PassThru'  = $true
    }
    if ($Credential -ne [System.Management.Automation.PSCredential]::Empty -and $null -ne $Credential) {
        $params.Add('Credential', $Credential)
    }

    if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
        $cert = Get-SdnCertificate -Path 'Cert:\LocalMachine\My' -Thumbprint $Thumbprint
    }
    else {
        $params.Add('ComputerName', $NetworkController)
        $cert = Invoke-PSRemoteCommand -ComputerName $NetworkController -Credential $Credential -ScriptBlock {
            param([Parameter(Position = 0)][String]$param1, [Parameter(Position = 1)][String]$param2)
            Get-SdnCertificate -Path $param1 -Thumbprint $param2
        } -ArgumentList @('Cert:\LocalMachine\My', $Thumbprint)
    }

    if ($null -eq $cert) {
        throw New-Object System.NullReferenceException("Unable to locate $($Thumbprint)")
    }
    if ($cert.Count -ge 2) {
        throw New-Object System.Exception("Duplicate certificates located that match $($Thumbprint)")
    }

    switch ($Command) {
        'Set-NetworkController' {
            $params.Add('ServerCertificate', $cert)
        }
        'Set-NetworkControllerCluster' {
            $params.Add('CredentialEncryptionCertificate', $cert)
        }
        'Set-NetworkControllerNode' {
            $ncNode = Get-SdnNetworkControllerSFNode -NetworkController $NetworkController -Name $Name -Credential $Credential

            $params.Add('Name', $ncNode.Name)
            $params.Add('NodeCertificate', $cert)
        }
    }

    $waitBeforeRetry = $false
    while ($true) {
        $retryAttempt++
        switch ($Command) {
            'Set-NetworkController' {
                $currentCertThumbprint = (Get-SdnNetworkControllerRestCertificate).Thumbprint
            }
            'Set-NetworkControllerCluster' {
                $currentCertThumbprint = (Get-NetworkControllerCluster).CredentialEncryptionCertificate.Thumbprint
            }
            'Set-NetworkControllerNode' {
                $currentCert = Invoke-PSRemoteCommand -ComputerName $NetworkController -Credential $Credential -ScriptBlock {
                    Get-SdnNetworkControllerNodeCertificate
                } -ErrorAction Stop
                $currentCertThumbprint = $currentCert.Thumbprint
            }
        }

        # if the certificate already matches what has been configured, then break out of the loop
        if ($currentCertThumbprint -ieq $Thumbprint) {
            "{0} has been updated to use certificate thumbprint {1}" -f $Command.Split('-')[1], $currentCertThumbprint | Trace-Output
            break
        }

        if ($stopWatch.Elapsed.TotalMinutes -ge $timeoutInMinutes) {
            throw New-Object System.TimeoutException("Rotate of certificate did not complete within the alloted time.")
        }

        if ($retryAttempt -ge $MaxRetry) {
            throw New-Object System.Exception("Rotate of certificate exceeded maximum number of retries.")
        }

        # if we have not started operation, or we hit a retryable error
        # then invoke the command to start the certificate rotate
        try {
            if ($waitBeforeRetry) {
                "Waiting 5 minutes before retrying operation..." | Trace-Output
                Start-Sleep -Seconds 300
            }

            "Command:{0} Params: {1}" -f $Command, ($params | ConvertTo-Json) | Trace-Output -Level:Verbose
            switch ($Command) {
                'Set-NetworkController' {
                    "Invoking {0} to configure thumbprint {1}" -f $Command, $cert.Thumbprint | Trace-Output
                    Set-NetworkController @params
                }
                'Set-NetworkControllerCluster' {
                    "Invoking {0} to configure thumbprint {1}" -f $Command, $cert.Thumbprint | Trace-Output
                    Set-NetworkControllerCluster @params
                }
                'Set-NetworkControllerNode' {
                    "Invoking {0} to configure thumbprint {1} for {2}" -f $Command, $cert.Thumbprint, $params.Name | Trace-Output
                    Set-NetworkControllerNode @params
                }
            }
        }
        catch [Microsoft.Management.Infrastructure.CimException] {
            switch -Wildcard ($_.Exception) {
                '*One or more errors occurred*' {
                    "Retryable exception caught`n`t$_" | Trace-Output -Level:Warning
                    $waitBeforeRetry = $true
                    break
                }

                '*A generic error has occurred*' {
                    "Retryable exception caught`n`t$_" | Trace-Output -Level:Warning
                    $waitBeforeRetry = $true
                    break
                }

                '*The I/O operation has been aborted because of either a thread exit or an application request*' {
                    "Retryable exception caught`n`t$_" | Trace-Output -Level:Warning
                    $waitBeforeRetry = $true
                    break
                }

                default {
                    $stopWatch.Stop()
                    throw $_
                }
            }
        }
        catch [InvalidOperationException] {
            if ($_.FullyQualifiedErrorId -ilike "*UpdateInProgress*") {
                "Networkcontroller is being updated by another operation.`n`t{0}" -f $fullyQualifiedErrorId | Trace-Output -Level:Warning
                $waitBeforeRetry = $true
            }
            else {
                $stopWatch.Stop()
                throw $_
            }
        }
        catch {
            $stopWatch.Stop()
            throw $_
        }
    }

    $stopWatch.Stop()
    return $currentCertThumbprint
}

function New-NetworkControllerClusterSecret {
    <#
    .SYNOPSIS
        Decrypt the current secret in ClusterManifest and Generate new one if decrypt success.
    .PARAMETER NcVMs
        The list of Network Controller VMs.
    .PARAMETER NcRestName
        The Network Controller REST Name in FQDN format.
    .PARAMETER ManifestFolder
        The Manifest Folder contains the orginal Manifest Files.
    .PARAMETER ManifestFolderNew
        The New Manifest Folder contains the new Manifest Files. Updated manifest file save here.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $OldEncryptedSecret,
        [Parameter(Mandatory = $true)]
        [String]
        $NcRestCertThumbprint,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $decryptedText = Invoke-ServiceFabricDecryptText -CipherText $OldEncryptedSecret

    if($null -eq $decryptedText)
    {
        throw New-Object System.NotSupportedException("Failed to decrypt the secret.")
    }

    $newEncryptedSecret = Invoke-ServiceFabricEncryptText -CertThumbPrint $NcRestCertThumbprint -Text $decryptedText -StoreName MY -StoreLocation LocalMachine -CertStore

    $newDecryptedText = Invoke-ServiceFabricDecryptText -CipherText $newEncryptedSecret

    if ($newDecryptedText -eq $decryptedText) {
        "GOOD, new key and old key are same. Ready for use" | Trace-Output
    }
    else {
        throw New-Object System.NotSupportedException("Decrypted text by new certificate is not matching the old one. We cannot continue.")
    }
    if($null -eq $newEncryptedSecret)
    {
        throw New-Object System.NotSupportedException("Failed to encrypt the secret with new certificate")
    }

    return $newEncryptedSecret
}

function Start-SdnExpiredCertificateRotation {
    <#
    .SYNOPSIS
        Start the Network Controller Certificate Update.
    .DESCRIPTION
        Start the Network Controller Certificate Update.
        This will use the latest issued certificate on each of the NC VMs to replace existing certificates. Ensure below before execute this command:
        - NC Rest Certificate and NC Node certificate created on each NC and trusted.
        - "Network Service" account have read access to the private file of the new certificates.
        - NC Rest Certificate need to be trusted by all SLB MUX VMs and SDN Hosts.

        For Self-Signed Certificate. This can also be created by 'New-NetworkControllerCertificate'. To get more details, run 'Get-Help New-NetworkControllerCertificate'

        About SDN Certificate Requirement:
        https://docs.microsoft.com/en-us/windows-server/networking/sdn/security/sdn-manage-certs

    .PARAMETER CertRotateConfig
        The Config generated by New-SdnCertificateRotationConfig to include NC REST certificate thumbprint and node certificate thumbprint.
    .EXAMPLE
        Start-SdnExpiredCertificateRotation -NetworkController nc01
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]
        $CertRotateConfig,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $NcUpdateFolder = "$(Get-WorkingDirectory)\NcCertUpdate_{0}" -f (Get-FormattedDateTimeUTC)
    $ManifestFolder = "$NcUpdateFolder\manifest"
    $ManifestFolderNew = "$NcUpdateFolder\manifest_new"

    $stopServiceFabricSB = {
        Stop-Service -Name 'FabricHostSvc' -Force -ErrorAction Ignore 3>$null # redirect warning to null
        if ((Get-Service -Name 'FabricHostSvc' -ErrorAction Ignore).Status -eq 'Stopped') {
            return $true
        }
        else {
            return $false
        }
    }

    $NcInfraInfo = Get-SdnNetworkControllerInfoOffline -Credential $Credential
    "Network Controller information detected:`n`tClusterCredentialType: {0}`n`tRestName: {1}" -f $NcInfraInfo.ClusterCredentialType, $NcInfraInfo.NcRestName | Trace-Output
    $NcNodeList = $NcInfraInfo.NodeList

    if ($null -eq $NcNodeList -or $NcNodeList.Count -eq 0) {
        throw New-Object System.NullReferenceException("Failed to get NC Node List from NetworkController: $(HostName)")
    }

    Trace-Output -Message "NcNodeList: $($NcNodeList.IpAddressOrFQDN)"
    Trace-Output -Message "Validate CertRotateConfig"
    if(!(Test-SdnCertificateRotationConfig -NcNodeList $NcNodeList -CertRotateConfig $CertRotateConfig -Credential $Credential)){
        Trace-Output -Message "Invalid CertRotateConfig, please correct the configuration and try again" -Level:Error
        return
    }

    if ([String]::IsNullOrEmpty($NcInfraInfo.NcRestName)) {
        Trace-Output -Message "Failed to get NcRestName using current secret certificate thumbprint. This might indicate the certificate not found on $(HOSTNAME). We won't be able to recover." -Level:Error
        throw New-Object System.NotSupportedException("Current NC Rest Cert not found, Certificate Rotation cannot be continue.")
    }

    if (Test-Path $NcUpdateFolder) {
        $items = Get-ChildItem $NcUpdateFolder
        if ($items.Count -gt 0) {
            $confirmCleanup = Read-Host "The Folder $NcUpdateFolder not empty. Need to be cleared. Enter Y to confirm"
            if ($confirmCleanup -eq "Y") {
                $items | Remove-Item -Force -Recurse
            }
            else {
                return
            }
        }
    }

    # stop service fabric service
    Trace-Output -Message "Stopping Service Fabric Service"
    $stopSfService = Invoke-PSRemoteCommand -ComputerName $NcNodeList.IpAddressOrFQDN -Credential $Credential -ScriptBlock $stopServiceFabricSB `
    -AsJob -PassThru -Activity 'Stopping Service Fabric Service on Network Controller' -ExecutionTimeOut 900

    # enumerate the results of stopping service fabric service
    # if any of the service fabric service is not stopped, throw an exception as we do not want to proceed further
    $stopSfService | ForEach-Object {
        if ($_) {
            "Service Fabric Service stopped on {0}" -f $_.PSComputerName | Trace-Output
        }
        else {
            throw "Failed to stop Service Fabric Service on $($_.PSComputerName)"
        }
    }

    Trace-Output -Message "Step 1 Copy manifests and settings.xml from Network Controller"
    Copy-ServiceFabricManifestFromNetworkController -NcNodeList $NcNodeList -ManifestFolder $ManifestFolder -ManifestFolderNew $ManifestFolderNew -Credential $Credential

    # Step 2 Update certificate thumbprint
    Trace-Output -Message "Step 2 Update certificate thumbprint and secret in manifest"
    Update-NetworkControllerCertificateInManifest -NcNodeList $NcNodeList -ManifestFolder $ManifestFolder -ManifestFolderNew $ManifestFolderNew -CertRotateConfig $CertRotateConfig -Credential $Credential

    # Step 3 Copy the new files back to the NC vms
    Trace-Output -Message "Step 3 Copy the new files back to the NC vms"
    Copy-ServiceFabricManifestToNetworkController -NcNodeList $NcNodeList -ManifestFolder $ManifestFolderNew -Credential $Credential

    # Step 5 Start FabricHostSvc and wait for SF system service to become healty
    Trace-Output -Message "Step 4 Start FabricHostSvc and wait for SF system service to become healty"
    Trace-Output -Message "Step 4.1 Update Network Controller Certificate ACL to allow 'Network Service' Access"
    Update-NetworkControllerCertificateAcl -NcNodeList $NcNodeList -CertRotateConfig $CertRotateConfig -Credential $Credential
    Trace-Output -Message "Step 4.2 Start Service Fabric Host Service and wait"
    $clusterHealthy = Wait-ServiceFabricClusterHealthy -NcNodeList $NcNodeList -CertRotateConfig $CertRotateConfig -Credential $Credential
    Trace-Output -Message "ClusterHealthy: $clusterHealthy"
    if($clusterHealthy -ne $true){
        throw New-Object System.NotSupportedException("Cluster unheathy after manifest update, we cannot continue with current situation")
    }
    # Step 6 Invoke SF Cluster Upgrade
    Trace-Output -Message "Step 5 Invoke SF Cluster Upgrade"
    Update-ServiceFabricCluster -NcNodeList $NcNodeList -CertRotateConfig $CertRotateConfig -ManifestFolderNew $ManifestFolderNew -Credential $Credential
    $clusterHealthy = Wait-ServiceFabricClusterHealthy -NcNodeList $NcNodeList -CertRotateConfig $CertRotateConfig -Credential $Credential
    Trace-Output -Message "ClusterHealthy: $clusterHealthy"
    if($clusterHealthy -ne $true){
        throw New-Object System.NotSupportedException("Cluster unheathy after cluster update, we cannot continue with current situation")
    }

    # Step 7 Fix NC App
    Trace-Output -Message "Step 6 Fix NC App"
    Trace-Output -Message "Step 6.1 Updating Network Controller Global and Cluster Config"
    if ($NcInfraInfo.ClusterCredentialType -eq "X509") {
        Update-NetworkControllerConfig -NcNodeList $NcNodeList -CertRotateConfig $CertRotateConfig -Credential $Credential
    }

    # Step 7 Restart
    Trace-Output -Message "Step 7 Restarting Service Fabric Cluster after configuration change"
    $clusterHealthy = Wait-ServiceFabricClusterHealthy -NcNodeList $NcNodeList -CertRotateConfig $CertRotateConfig -Credential $Credential -Restart
}

function Test-NetworkControllerIsHealthy {
    try {
        $null = Get-NetworkController -ErrorAction 'Stop'
        return $true
    }
    catch {
        "Network Controller is not healthy" | Trace-Output -Level:Error
        return $false
    }
}

function Update-NetworkControllerCertificateAcl {
    <#
    .SYNOPSIS
        Update the Network Controller Certificate to grant Network Service account read access to the private key.
    .PARAMETER NcNodeList
        The NcNodeList that retrieved via Get-SdnNetworkControllerInfoOffline.
    .PARAMETER CertRotateConfig
        The Config generated by New-SdnCertificateRotationConfig to include NC REST certificate thumbprint and node certificate thumbprint.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $NcNodeList,
        [Parameter(Mandatory = $true)]
        [hashtable]
        $CertRotateConfig,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $NcRestCertThumbprint = $CertRotateConfig["NcRestCert"]

        foreach ($ncNode in $NcNodeList) {
            $ncNodeCertThumbprint = $CertRotateConfig[$ncNode.NodeName.ToLower()]
            Invoke-PSRemoteCommand -ComputerName $ncNode.IpAddressOrFQDN -Credential $Credential -ScriptBlock {
                param([Parameter(Position = 0)][String]$param1, [Parameter(Position = 1)][String]$param2)
                Set-SdnCertificateAcl -Path $param1 -Thumbprint $param2
            } -ArgumentList @('Cert:\LocalMachine\My', $NcRestCertThumbprint)

            if ($CertRotateConfig["ClusterCredentialType"] -ieq "X509") {
                Invoke-PSRemoteCommand -ComputerName $ncNode.IpAddressOrFQDN -Credential $Credential -ScriptBlock {
                    param([Parameter(Position = 0)][String]$param1, [Parameter(Position = 1)][String]$param2)
                    Set-SdnCertificateAcl -Path $param1 -Thumbprint $param2
                } -ArgumentList @('Cert:\LocalMachine\My', $ncNodeCertThumbprint)
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Update-NetworkControllerCertificateInManifest {
    <#
    .SYNOPSIS
        Update Network Controller Manifest File with new Network Controller Certificate.
    .PARAMETER NcVMs
        The list of Network Controller VMs.
    .PARAMETER ManifestFolder
        The Manifest Folder contains the orginal Manifest Files.
    .PARAMETER ManifestFolderNew
        The New Manifest Folder contains the new Manifest Files. Updated manifest file save here.
    .PARAMETER CertRotateConfig
        The Config generated by New-SdnCertificateRotationConfig to include NC REST certificate thumbprint and node certificate thumbprint.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $NcNodeList,
        [Parameter(Mandatory = $true)]
        [String]
        $ManifestFolder,
        [Parameter(Mandatory = $true)]
        [String]
        $ManifestFolderNew,
        [Parameter(Mandatory = $true)]
        [hashtable]
        $CertRotateConfig,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    if ($NcNodeList.Count -eq 0) {
        throw New-Object System.NotSupportedException("NcNodeList is empty")
    }

    # Prepare the cert thumbprint to be used
    # Update certificates ClusterManifest.current.xml

    $clusterManifestXml = [xml](Get-Content "$ManifestFolder\ClusterManifest.current.xml")

    if ($null -eq $clusterManifestXml) {
        Trace-Output -Message "ClusterManifest not found at $ManifestFolder\ClusterManifest.current.xml" -Level:Error
        throw
    }

    $NcRestCertThumbprint = $CertRotateConfig["NcRestCert"]

    # Update encrypted secret
    # Get encrypted secret from Cluster Manifest
    $fileStoreServiceSection = ($clusterManifestXml.ClusterManifest.FabricSettings.Section | Where-Object name -eq FileStoreService)
    $OldEncryptedSecret = ($fileStoreServiceSection.Parameter | Where-Object Name -eq "PrimaryAccountNTLMPasswordSecret").Value
    $newEncryptedSecret = New-NetworkControllerClusterSecret -OldEncryptedSecret $OldEncryptedSecret -NcRestCertThumbprint $NcRestCertThumbprint -Credential $Credential

    # Update new encrypted secret in Cluster Manifest
    ($fileStoreServiceSection.Parameter | Where-Object Name -eq "PrimaryAccountNTLMPasswordSecret").Value = "$newEncryptedSecret"
    ($fileStoreServiceSection.Parameter | Where-Object Name -eq "SecondaryAccountNTLMPasswordSecret").Value = "$newEncryptedSecret"

    # Update SecretsCertificate to new REST Cert

    Trace-Output -Message "Updating SecretsCertificate with new rest cert thumbprint $NcRestCertThumbprint"
    $clusterManifestXml.ClusterManifest.Certificates.SecretsCertificate.X509FindValue = "$NcRestCertThumbprint"

    $securitySection = $clusterManifestXml.ClusterManifest.FabricSettings.Section | Where-Object Name -eq "Security"
    $ClusterCredentialType = $securitySection.Parameter | Where-Object Name -eq "ClusterCredentialType"

    $infrastructureManifestXml = [xml](Get-Content "$ManifestFolder\InfrastructureManifest.xml")

    # Update Node Certificate to new Node Cert if the ClusterCredentialType is X509 certificate
    if($ClusterCredentialType.Value -eq "X509")
    {
        foreach ($node in $clusterManifestXml.ClusterManifest.NodeTypes.NodeType) {
            $ncNode = $node.Name
            $ncNodeCertThumbprint = $CertRotateConfig[$ncNode.ToLower()]
            Write-Verbose "Updating node $ncNode with new thumbprint $ncNodeCertThumbprint"
            $node.Certificates.ClusterCertificate.X509FindValue = "$ncNodeCertThumbprint"
            $node.Certificates.ServerCertificate.X509FindValue = "$ncNodeCertThumbprint"
            $node.Certificates.ClientCertificate.X509FindValue = "$ncNodeCertThumbprint"
        }

        # Update certificates InfrastructureManifest.xml

        foreach ($node in $infrastructureManifestXml.InfrastructureInformation.NodeList.Node) {
            $ncNodeCertThumbprint = $CertRotateConfig[$node.NodeName.ToLower()]
            $node.Certificates.ClusterCertificate.X509FindValue = "$ncNodeCertThumbprint"
            $node.Certificates.ServerCertificate.X509FindValue = "$ncNodeCertThumbprint"
            $node.Certificates.ClientCertificate.X509FindValue = "$ncNodeCertThumbprint"
        }
    }

    # Update certificates for settings.xml
    foreach ($ncNode in $NcNodeList) {
        $ncVm = $ncNode.IpAddressOrFQDN
        $settingXml = [xml](Get-Content "$ManifestFolder\$ncVm\Settings.xml")
        if($ClusterCredentialType.Value -eq "X509")
        {
            $ncNodeCertThumbprint = $CertRotateConfig[$ncNode.NodeName.ToLower()]
            $fabricNodeSection = $settingXml.Settings.Section | Where-Object Name -eq "FabricNode"
            $parameterToUpdate = $fabricNodeSection.Parameter | Where-Object Name -eq "ClientAuthX509FindValue"
            $parameterToUpdate.Value = "$ncNodeCertThumbprint"
            $parameterToUpdate = $fabricNodeSection.Parameter | Where-Object Name -eq "ServerAuthX509FindValue"
            $parameterToUpdate.Value = "$ncNodeCertThumbprint"
            $parameterToUpdate = $fabricNodeSection.Parameter | Where-Object Name -eq "ClusterX509FindValue"
            $parameterToUpdate.Value = "$ncNodeCertThumbprint"
        }

        # Update encrypted secret in settings.xml
        $fileStoreServiceSection = $settingXml.Settings.Section | Where-Object Name -eq "FileStoreService"
        ($fileStoreServiceSection.Parameter | Where-Object Name -eq "PrimaryAccountNTLMPasswordSecret").Value = "$newEncryptedSecret"
        ($fileStoreServiceSection.Parameter | Where-Object Name -eq "SecondaryAccountNTLMPasswordSecret").Value = "$newEncryptedSecret"

        $settingXml.Save("$ManifestFolderNew\$ncVm\Settings.xml")
    }

    $infrastructureManifestXml.Save("$ManifestFolderNew\InfrastructureManifest.xml")
    $clusterManifestXml.Save("$ManifestFolderNew\ClusterManifest.current.xml")
}

function Update-NetworkControllerConfig {
    <#
    .SYNOPSIS
        Update the Network Controller Application Global Config with new certificate info. This to be run on Network Controller only.
    .PARAMETER NcNodeList
        The NcNodeList that retrieved via Get-SdnNetworkControllerInfoOffline.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER CertRotateConfig
        The Config generated by New-SdnCertificateRotationConfig to include NC REST certificate thumbprint and node certificate thumbprint.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $NcNodeList,
        [Parameter(Mandatory = $true)]
        [hashtable]
        $CertRotateConfig,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $globalConfigUri = "GlobalConfiguration"
    $clusterConfigUri = "ClusterConfiguration"
    $globalConfigs = Get-SdnServiceFabricClusterConfig -Uri $globalConfigUri
    $clusterConfigs = Get-SdnServiceFabricClusterConfig -Uri $clusterConfigUri

    foreach ($ncNode in $NcNodeList) {
        $nodeCertThumbprint = $CertRotateConfig[$ncNode.NodeName.ToLower()]
        if($null -eq $nodeCertThumbprint){
            throw New-Object System.NotSupportedException("NodeCertificateThumbprint not found for $($ncNode.NodeName)")
        }
        $thumbprintPropertyName = "{0}.ClusterCertThumbprint" -f $ncNode.NodeName
        # Global Config property name like Global.Version.NodeName.ClusterCertThumbprint
        $thumbprintProperty = $globalConfigs | Where-Object Name -Match $thumbprintPropertyName

        if($null -ne $thumbprintProperty){
            "GlobalConfiguration: Property $($thumbprintProperty.Name) will be updated from $($thumbprintProperty.Value) to $nodeCertThumbprint" | Trace-Output
            Set-SdnServiceFabricClusterConfig -Uri $globalConfigUri -Name $thumbprintProperty.Name.ToString() -Value $nodeCertThumbprint
        }

        # Cluster Config property name like NodeName.ClusterCertThumbprint
        $thumbprintProperty = $clusterConfigs | Where-Object Name -ieq $thumbprintPropertyName

        # If NodeName.ClusterCertThumbprint exist (for Server 2022 +), Update
        if($null -ne $thumbprintProperty){
            "ClusterConfiguration: Property $($thumbprintProperty.Name) will be updated from $($thumbprintProperty.Value) to $nodeCertThumbprint" | Trace-Output
            Set-SdnServiceFabricClusterConfig -Uri $clusterConfigUri -Name $thumbprintProperty.Name.ToString() -Value $nodeCertThumbprint
        }

        $certProperty = $clusterConfigs | Where-Object Name -ieq $ncNode.NodeName
        if($null -ne $certProperty){
            $nodeCert = Invoke-PSRemoteCommand -ComputerName $ncNode.IpAddressOrFQDN -Credential $Credential -ScriptBlock{
                param([Parameter(Position = 0)][String]$param1, [Parameter(Position = 1)][String]$param2)
                return Get-SdnCertificate -Path $param1 -Thumbprint $param2
            } -ArgumentList @('Cert:\LocalMachine\My', $nodeCertThumbprint)

            "ClusterConfiguration: Property $($certProperty.Name) will be updated From :`n$($certProperty.Value) `nTo : `n$nodeCert" | Trace-Output
            Set-SdnServiceFabricClusterConfig -Uri $clusterConfigUri -Name $certProperty.Name.ToString() -Value $nodeCert.GetRawCertData()
        }
    }
}

function Update-ServiceFabricCluster {
    <#
    .SYNOPSIS
        Upgrade the Service Fabric Cluster via Start-ServiceFabricClusterUpgrade and wait for the cluster to become healthy.
    .PARAMETER NcNodeList
        The list of Network Controller Nodes.
    .PARAMETER ClusterCredentialType
        X509, Windows or None.
    .PARAMETER ManifestFolderNew
        The New Manifest Folder contains the new Manifest Files.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $NcNodeList,
        [Parameter(Mandatory = $true)]
        [String]
        $ManifestFolderNew,
        [Parameter(Mandatory = $true)]
        [hashtable]
        $CertRotateConfig,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    if ($NcNodeList.Count -eq 0) {
        throw New-Object System.NotSupportedException("NcNodeList is empty")
    }

    # Update the cluster manifest version to 1
    $clusterManifestXml = [xml](Get-Content "$ManifestFolderNew\ClusterManifest.current.xml")
    $currentVersionArray = $clusterManifestXml.ClusterManifest.Version.Split('.')
    $minorVersionIncrease = [int]$currentVersionArray[$currentVersionArray.Length - 1] + 1
    $currentVersionArray[$currentVersionArray.Length - 1] = $minorVersionIncrease
    $newVersionString = $currentVersionArray -Join '.'
    "Upgrade Service Fabric from $($clusterManifestXml.ClusterManifest.Version) to $newVersionString" | Trace-Output
    $clusterManifestXml.ClusterManifest.Version = $newVersionString
    $clusterManifestXml.Save("$ManifestFolderNew\ClusterManifest_new.xml")

    $currentNcNode = $null
    # Start Service Fabric Service for each NC
    foreach ($ncNode in $NcNodeList) {
        if(Test-ComputerNameIsLocal -ComputerName $ncNode.IpAddressOrFQDN){
            $currentNcNode = $ncNode
        }
    }
    $certThumb = $CertRotateConfig[$currentNcNode.NodeName.ToLower()]

    $clusterManifestPath = "$ManifestFolderNew\ClusterManifest_new.xml"

    if (!(Test-Path $clusterManifestPath)) {
        Throw "Path $clusterManifestPath not found"
    }

    "Upgrading Service Fabric Cluster with ClusterManifest at $clusterManifestPath" | Trace-Output

    # Sometimes access denied returned for the copy call, retry here to workaround this.
    $maxRetry = 3
    while($maxRetry -gt 0){
        try{
            if($CertRotateConfig["ClusterCredentialType"] -ieq "X509"){
                "Connecting to Service Fabric Cluster using cert with thumbprint: {0}" -f $certThumb | Trace-Output
                Connect-ServiceFabricCluster -X509Credential -FindType FindByThumbprint -FindValue $certThumb -ConnectionEndpoint "$($currentNcNode.IpAddressOrFQDN):49006" | Out-Null
            }
            else{
                Connect-ServiceFabricCluster | Out-Null
            }
            Copy-ServiceFabricClusterPackage -Config -ImageStoreConnectionString "fabric:ImageStore" -ClusterManifestPath  $clusterManifestPath -ClusterManifestPathInImageStore "ClusterManifest.xml"
            break
        }catch{
            "Copy-ServiceFabricClusterPackage failed with exception $_.Exception. Retry $(4 - $maxRetry)/3 after 60 seconds" | Trace-Output -Level:Warning
            Start-Sleep -Seconds 60
            $maxRetry --
        }
    }

    Register-ServiceFabricClusterPackage -Config -ClusterManifestPath "ClusterManifest.xml"
    Start-ServiceFabricClusterUpgrade -ClusterManifestVersion $NewVersionString -Config -UnmonitoredManual -UpgradeReplicaSetCheckTimeoutSec 30

    while ($true) {
        $upgradeStatus = Get-ServiceFabricClusterUpgrade
        "Current upgrade state: $($upgradeStatus.UpgradeState) UpgradeDomains: $($upgradeStatus.UpgradeDomains)" | Trace-Output
        if ($upgradeStatus.UpgradeState -eq "RollingForwardPending") {
            $nextNode = $upgradeStatus.NextUpgradeDomain
            "Next node to upgrade $nextNode" | Trace-Output
            try{
                Resume-ServiceFabricClusterUpgrade -UpgradeDomainName $nextNode
                # Catch exception for resume call, as sometimes, the upgrade status not updated intime caused duplicate resume call.
            }catch{
                "Exception in Resume-ServiceFabricClusterUpgrade $_.Exception" | Trace-Output -Level:Warning
            }
        }
        elseif ($upgradeStatus.UpgradeState -eq "Invalid" `
                -or $upgradeStatus.UpgradeState -eq "Failed") {
            Throw "Something wrong with the upgrade"
        }
        elseif ($upgradeStatus.UpgradeState -eq "RollingBackCompleted" `
                -or $upgradeStatus.UpgradeState -eq "RollingForwardCompleted") {
            "Upgrade has been completed" | Trace-Output
            break
        }
        else {
            "Waiting for current node upgrade to complete" | Trace-Output
        }

        Start-Sleep -Seconds 60
    }
}

function Wait-NetworkControllerAppHealthy {
    <#
    .SYNOPSIS
        Query the Network Controller App Health Status. Wait for the Network Controller App become healthy when $Interval specified.
    .PARAMETER NetworkController
        Specifies one of the Network Controller VM name.
    .PARAMETER Interval
        App healh status query interval until the App become healthy, default to 0 means no retry of the health status query.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $NetworkController,
        [Parameter(Mandatory = $false)]
        [Int32]
        $Interval = 0,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $scriptBlock = {
            param (
                [Int32]
                $Interval = 0
            )
            $isApplicationHealth = $false;
            Write-Host "[$(HostName)] Query Network Controller App Health"
            while($isApplicationHealth -ne $true){
                #Connect-ServiceFabricCluster -X509Credential -FindType FindByThumbprint -FindValue $certThumb  -ConnectionEndpoint "$($NodeFQDN):49006" | Out-Null
                #Cluster should have been back to normal when reach here use default parameters to connect
                Connect-ServiceFabricCluster | Out-Null
                $clusterHealth = Get-ServiceFabricClusterHealth
                if ($clusterHealth.AggregatedHealthState -ne "Ok") {
                    if ($clusterHealth.NodeHealthStates -ne "Ok") {
                        Get-ServiceFabricNode -StatusFilter All | Format-Table Nodename, Nodestatus, HealthState, IpAddressOrFQDN, NodeUptime -autosize
                    }
                    $applicationStatus = Get-ServiceFabricApplication -ApplicationName fabric:/NetworkController
                    if ($applicationStatus.HealthState -ne "Ok") {
                        $applicationStatus | Format-Table ApplicationName, ApplicationStatus, HealthState -AutoSize
                        $services = Get-ServiceFabricService -ApplicationName fabric:/NetworkController
                        $allServiceHealth = $true;
                        foreach ($service in $services) {
                            if($service.HealthState -notlike "Ok"){
                                $allServiceHealth = $false;
                            }
                        }
                        if($allServiceHealth -and $services.Count -gt 0)
                        {
                            $isApplicationHealth = $true
                            break
                        }

                        $services | Format-Table ServiceName, ServiceStatus, HealthState -AutoSize
                    }
                    else {
                        $isApplicationHealth = $true
                    }

                    $systemStatus = Get-ServiceFabricService -ApplicationName fabric:/System
                    if ($systemStatus.HealthState -ne "Ok") {
                        $systemStatus | Format-Table ServiceName, ServiceStatus, HealthState -AutoSize
                    }
                }else{
                    $isApplicationHealth = $true;
                }

                Write-Host "[$(HostName)] Current Network Controller Health Status: $isApplicationHealth"
                if($Interval -gt 0)
                {
                    Start-Sleep -Seconds $Interval
                }else{
                    break
                }
            }
        }

        if (-NOT ($PSBoundParameters.ContainsKey('NetworkController')))
        {
            Invoke-Command -ScriptBlock $scriptBlock -ArgumentList $Interval
        }
        else{
            Invoke-Command -ComputerName $NetworkController -ScriptBlock $scriptBlock -ArgumentList $Interval -Credential $Credential
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Wait-ServiceFabricClusterHealthy {
    <#
    .SYNOPSIS
        Start the FabricHostSvc on each of the Network Controller VM and wait for the service fabric service to become healthy.
    .PARAMETER NcVMs
        The list of Network Controller VMs.
    .PARAMETER ClusterCredentialType
        X509, Windows or None.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $NcNodeList,

        [Parameter(Mandatory = $true)]
        [hashtable]
        $CertRotateConfig,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [switch]
        $Restart
    )

    try {
        $currentNcNode = $null

        # Start Service Fabric Service for each NC
        foreach ($ncNode in $NcNodeList) {
            if(Test-ComputerNameIsLocal -ComputerName $ncNode.IpAddressOrFQDN){
                $currentNcNode = $ncNode
            }

            Invoke-PSRemoteCommand -ComputerName $ncNode.IpAddressOrFQDN -Credential $Credential -ScriptBlock {
                param([Parameter(Position = 0)][Switch]$param1)
                if ($param) {
                    Stop-Service -Name 'FabricHostSvc' -Force
                    Start-Sleep -Seconds 5
                }

                Start-Service -Name 'FabricHostSvc'
            } -ArgumentList $Restart
        }

        Trace-Output -Message "Sleeping 60s to wait for Serice Fabric Service to be ready"
        Start-Sleep -Seconds 60
        "Waiting for service fabric service healthy" | Trace-Output
        $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName + "." + (get-ciminstance win32_computersystem).Domain
        $certThumb = $CertRotateConfig[$currentNcNode.NodeName.ToLower()]

        $maxRetry = 10
        $clusterConnected = $false
        while ($maxRetry -gt 0) {
            if(!$clusterConnected){
                try{
                    "Service fabric cluster connect attempt $(11 - $maxRetry)/10" | Trace-Output
                    if ($CertRotateConfig["ClusterCredentialType"] -ieq "X509") {
                        "Connecting to Service Fabric Cluster using cert with thumbprint: {0}" -f $certThumb | Trace-Output
                        Connect-ServiceFabricCluster -X509Credential -FindType FindByThumbprint -FindValue $certThumb  -ConnectionEndpoint "$($NodeFQDN):49006" | Out-Null
                    }
                    else {
                        Connect-ServiceFabricCluster | Out-Null
                    }
                    $clusterConnected = $true
                }catch{
                    $maxRetry --
                    continue
                }
            }

            if($clusterConnected){
                $services = @()
                $services = Get-ServiceFabricService -ApplicationName fabric:/System
                $allServiceHealth = $true
                if ($services.Count -eq 0) {
                    "No service fabric services retrieved yet" | Trace-Output -Level:Warning
                }

                foreach ($service in $services) {
                    if ($service.ServiceStatus -ne "Active" -or $service.HealthState -ne "Ok" ) {
                        "$($service.ServiceName) ServiceStatus: $($service.ServiceStatus) HealthState: $($service.HealthState)" | Trace-Output -Level:Warning
                        $allServiceHealth = $false
                    }
                }
                if ($allServiceHealth -and $services.Count -gt 0) {
                    "All service fabric services marked healthy" | Trace-Output
                    return $allServiceHealth
                }

                Start-Sleep -Seconds 10
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnServiceFabricApplication {
    <#
    .SYNOPSIS
        Gets the health of a Service Fabric application from Network Controller.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER ApplicationName
        A service fabric application name that exists on the provided ring, such as fabric:/NetworkController.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnServiceFabricApplication -NetworkController 'NC01' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [String]$ApplicationName = 'fabric:/NetworkController',

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sb = {
        # check if service fabric service is running
        $serviceState = Get-Service -Name 'FabricHostSvc' -ErrorAction Stop
        if ($serviceState.Status -ne 'Running') {
            throw New-Object System.Exception("Service Fabric Service is currently not running.")
        }

        # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
        $null = Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null
        Get-ServiceFabricApplication
    }

    try {
        Invoke-SdnServiceFabricCommand -NetworkController $NetworkController -Credential $Credential -ScriptBlock $sb -ArgumentList @($ApplicationName)
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnServiceFabricApplicationHealth {
    <#
    .SYNOPSIS
        Gets the health of a Service Fabric application from Network Controller.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER ApplicationName
        A service fabric application name that exists on the provided ring, such as fabric:/NetworkController.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnServiceFabricApplicationHealth -NetworkController 'NC01' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [String]$ApplicationName = 'fabric:/NetworkController',

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sb = {
        param([string]$param1)
        # check if service fabric service is running
        $serviceState = Get-Service -Name 'FabricHostSvc' -ErrorAction Stop
        if ($serviceState.Status -ne 'Running') {
            throw New-Object System.Exception("Service Fabric Service is currently not running.")
        }

        # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
        $null = Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null
        Get-ServiceFabricApplicationHealth -ApplicationName $param1
    }

    try {
        Invoke-SdnServiceFabricCommand -NetworkController $NetworkController -Credential $Credential -ScriptBlock $sb -ArgumentList @($ApplicationName)
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnServiceFabricClusterConfig {
    <#
    .SYNOPSIS
        Gets Service Fabric Cluster Config Properties.
    .PARAMETER Uri
        The Uri to read properties from ClusterConfiguration, GlobalConfiguration
    .PARAMETER Name
        Property Name to filter the result. If not specified, it will return all properties.
    .EXAMPLE
        PS> Get-SdnServiceFabricClusterConfig -Uri "ClusterConfiguration"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('GlobalConfiguration', 'ClusterConfiguration')]
        [String]$Uri,

        [Parameter(Mandatory = $false)]
        [String]$Name
    )

    Confirm-IsNetworkController
    $results = [System.Collections.ArrayList]::new()

    try {
        Connect-ServiceFabricCluster | Out-Null

        $client = [System.Fabric.FabricClient]::new()
        $result = $null
        $absoluteUri = "fabric:/NetworkController/$Uri"
        $binaryMethod = [System.Fabric.NamedProperty].getmethod("GetValue").MakeGenericMethod([byte[]])
        $stringMethod = [System.Fabric.NamedProperty].getmethod("GetValue").MakeGenericMethod([string])

        do {
            $result = $client.PropertyManager.EnumeratePropertiesAsync($absoluteUri, $true, $result).Result
            $result.GetEnumerator() | ForEach-Object {
                $propertyObj = [PSCustomObject]@{
                    Name  = $_.Metadata.PropertyName
                    Value = $null
                }

                if ($_.Metadata.TypeId -ieq "string") {
                    $value = $stringMethod.Invoke($_, $null);
                    $propertyObj.Value = $value

                }
                elseif ($_.Metadata.TypeId -ieq "binary") {
                    # only binary value exist is certificate
                    $value = $binaryMethod.Invoke($_, $null);
                    $certObj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($value)
                    $propertyObj.Value = $certObj
                }

                if ($PSBoundParameters.ContainsKey('Name')) {
                    # PropertyName is unique so when name found, return the list
                    if ($_.Metadata.PropertyName -ieq $Name) {
                        [void]$results.Add($propertyObj)
                        return $results
                    }
                }
                else {
                    [void]$results.Add($propertyObj)
                }
            }
        }
        while ($result.HasMoreData)

        return $results
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnServiceFabricClusterHealth {
    <#
    .SYNOPSIS
        Gets health information for a Service Fabric cluster from Network Controller.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnServiceFabricClusterHealth -NetworkController 'NC01' -Credential (Get-Credential)
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

    $sb = {
        # check if service fabric service is running
        $serviceState = Get-Service -Name 'FabricHostSvc' -ErrorAction Stop
        if ($serviceState.Status -ne 'Running') {
            throw New-Object System.Exception("Service Fabric Service is currently not running.")
        }

        # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
        $null = Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null
        Get-ServiceFabricClusterHealth
    }

    try {
        Invoke-SdnServiceFabricCommand -NetworkController $NetworkController -Credential $Credential -ScriptBlock $sb
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnServiceFabricClusterManifest {
    <#
    .SYNOPSIS
        Gets the Service Fabric cluster manifest, including default configurations for reliable services from Network Controller.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnServiceFabricClusterManifest -NetworkController 'NC01'
    .EXAMPLE
        PS> Get-SdnServiceFabricClusterManifest -NetworkController 'NC01' -Credential (Get-Credential)
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

    $sb = {
        # check if service fabric service is running
        $serviceState = Get-Service -Name 'FabricHostSvc' -ErrorAction Stop
        if ($serviceState.Status -ne 'Running') {
            throw New-Object System.Exception("Service Fabric Service is currently not running.")
        }

        # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
        $null = Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null
        Get-ServiceFabricClusterManifest
    }

    try {
        # in instances where Service Fabric is down/offline we want to catch any exceptions returned by Invoke-SdnServiceFabricCommand
        # and then fallback to getting the cluster manifest information from the file system directly
        try {
            $clusterManifest = Invoke-SdnServiceFabricCommand -NetworkController $NetworkController -ScriptBlock $sb -Credential $Credential
        }
        catch {
            $_ | Trace-Exception
            "Unable to retrieve ClusterManifest directly from Service Fabric. Attempting to retrieve ClusterManifest from file system" | Trace-Output -Level:Warning

            # we want to loop through if multiple NetworkController objects were passed into the cmdlet
            foreach ($obj in $NetworkController) {
                $clusterManifestScript = {
                    $clusterManifestFile = Get-ChildItem -Path "$env:ProgramData\Microsoft\Service Fabric" -Recurse -Depth 2 -Filter "ClusterManifest.current.xml" -ErrorAction SilentlyContinue
                    if ($clusterManifestFile) {
                        $clusterManifest = Get-Content -Path $clusterManifestFile.FullName -ErrorAction SilentlyContinue
                        return $clusterManifest
                    }

                    return $null
                }

                if (Test-ComputerNameIsLocal -ComputerName $obj) {
                    $xmlClusterManifest = Invoke-Command -ScriptBlock $clusterManifestScript
                }
                else {
                    $xmlClusterManifest = Invoke-PSRemoteCommand -ComputerName $obj -Credential $Credential -ScriptBlock $clusterManifestScript
                }

                # once the cluster manifest has been retrieved from the file system break out of the loop
                if ($xmlClusterManifest) {
                    "Successfully retrieved ClusterManifest from {0}" -f $obj | Trace-Output
                    $clusterManifest = $xmlClusterManifest
                    break
                }
            }
        }

        if ($null -eq $clusterManifest) {
            throw New-Object System.NullReferenceException("Unable to retrieve ClusterManifest from Network Controller")
        }

        if ($clusterManifest) {
            # Convert to native Powershell XML
            $xmlClusterManifest = [xml]$clusterManifest

            # Although the strings are encrypted, they should be sanitized anyway
            # Change PrimaryAccountNTLMPasswordSecret and SecondaryAccountNTLMPasswordSecret to removed_for_security_reasons
            (($xmlClusterManifest.ClusterManifest.FabricSettings.Section | Where-Object {$_.Name -eq "FileStoreService"}).Parameter | Where-Object {$_.Name -eq "PrimaryAccountNTLMPasswordSecret"}).Value = "removed_for_security_reasons"
            (($xmlClusterManifest.ClusterManifest.FabricSettings.Section | Where-Object {$_.Name -eq "FileStoreService"}).Parameter | Where-Object {$_.Name -eq "SecondaryAccountNTLMPasswordSecret"}).Value = "removed_for_security_reasons"

            # If we want to keep newlines and indents, but return a string, we need to use the writer class
            # $xmlClusterManifest.OuterXml does not keep the formatting
            $stringWriter = New-Object System.IO.StringWriter
            $writer = New-Object System.Xml.XmlTextwriter($stringWriter)
            $writer.Formatting = [System.XML.Formatting]::Indented

            # Write the manifest to the StringWriter
            $xmlClusterManifest.WriteContentTo($writer)

            # Return the manifest as a string
            return $stringWriter.ToString()
        }

        return $clusterManifest
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnServiceFabricNode {
    <#
    .SYNOPSIS
        Gets information for all nodes in a Service Fabric cluster for Network Controller.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER NodeName
        Specifies the name of the Service Fabric node whose information is being returned. If not specified, the cmdlet will return information for all the nodes in the cluster.
    .EXAMPLE
        PS> Get-SdnServiceFabricNode -NetworkController 'Prefix-NC01' -Credential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnServiceFabricNode -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -NodeName 'Prefix-NC02'
    .EXAMPLE
        PS> Get-SdnServiceFabricNode -NodeName 'Prefix-NC01'
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [System.String]$NodeName
    )

    $sfParams = @{
        NetworkController = $NetworkController
        Credential = $Credential
    }
    if ($NodeName) {
        $sfParams.Add('ArgumentList', @($NodeName))
    }

    $sb = {
        param([string]$param1)
        # check if service fabric service is running
        $serviceState = Get-Service -Name 'FabricHostSvc' -ErrorAction Stop
        if ($serviceState.Status -ne 'Running') {
            throw New-Object System.Exception("Service Fabric Service is currently not running.")
        }

        # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
        $null = Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null

        if ($param1) {
            Get-ServiceFabricNode -NodeName $param1
        }
        else {
            Get-ServiceFabricNode
        }
    }

    try {
        Invoke-SdnServiceFabricCommand @sfParams -ScriptBlock $sb
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnServiceFabricPartition {
    <#
    .SYNOPSIS
        Gets information about the partitions of a specified Service Fabric partition or service from Network Controller.
    .PARAMETER ApplicationName
        A service fabric application name that exists on the provided ring, such as fabric:/NetworkController.
    .PARAMETER ServiceName
        A service fabric service name that is under the provided ApplicationName on the provided ring, such as fabric:/NetworkController/ApiService.
    .PARAMETER ServiceTypeName
        A service fabric service TypeName, such as VSwitchService.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnServiceFabricPartition -PartitionId 1a7a780e-dbfe-46d3-92fb-76908a95ce54
    .EXAMPLE
        PS> Get-SdnServiceFabricPartition -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -ServiceTypeName 'ApiService'
    .EXAMPLE
        PS> Get-SdnServiceFabricPartition -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -ServiceName 'fabric:/NetworkController/ApiService'
    #>

    [CmdletBinding(DefaultParameterSetName = 'NamedService')]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String]$ApplicationName = 'fabric:/NetworkController',

        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [System.String]$ServiceName,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String]$ServiceTypeName,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'PartitionID')]
        [System.Guid]$PartitionId,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'PartitionID')]
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'PartitionID')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sfParams = @{
        Credential  = $Credential
        NetworkController = $NetworkController
    }

    switch ($PSCmdlet.ParameterSetName) {
        'NamedService' {
            $sfParams.Add('ArgumentList',@($ApplicationName, $ServiceName))
            $sb = {
                param([string]$param1, [string]$param2)
                # check if service fabric service is running
                $serviceState = Get-Service -Name 'FabricHostSvc' -ErrorAction Stop
                if ($serviceState.Status -ne 'Running') {
                    throw New-Object System.Exception("Service Fabric Service is currently not running.")
                }

                # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
                $null = Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null
                Get-ServiceFabricApplication -ApplicationName $param1 | Get-ServiceFabricService -ServiceName $param2 | Get-ServiceFabricPartition
            }
        }

        'NamedServiceTypeName' {
            $sfParams.Add('ArgumentList',@($ApplicationName, $ServiceTypeName))
            $sb = {
                param([string]$param1, [string]$param2)
                # check if service fabric service is running
                $serviceState = Get-Service -Name 'FabricHostSvc' -ErrorAction Stop
                if ($serviceState.Status -ne 'Running') {
                    throw New-Object System.Exception("Service Fabric Service is currently not running.")
                }

                # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
                $null = Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null
                Get-ServiceFabricApplication -ApplicationName $param1 | Get-ServiceFabricService -ServiceTypeName $param2 | Get-ServiceFabricPartition
            }
        }

        'PartitionID' {
            $sfParams.Add('ArgumentList',@($PartitionId))
            $sb = {
                param([Guid]$param1)
                # check if service fabric service is running
                $serviceState = Get-Service -Name 'FabricHostSvc' -ErrorAction Stop
                if ($serviceState.Status -ne 'Running') {
                    throw New-Object System.Exception("Service Fabric Service is currently not running.")
                }

                # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
                $null = Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null
                Get-ServiceFabricPartition -PartitionId $param1
            }
        }
    }

    try {
        Invoke-SdnServiceFabricCommand @sfParams -ScriptBlock $sb
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnServiceFabricReplica {
    <#
    .SYNOPSIS
        Gets Service Fabric replicas of a partition from Network Controller.
    .PARAMETER ApplicationName
        A service fabric application name that exists on the provided ring, such as fabric:/NetworkController.
    .PARAMETER ServiceName
        A service fabric service name that is under the provided ApplicationName on the provided ring, such as fabric:/NetworkController/ApiService.
    .PARAMETER ServiceTypeName
        A service fabric service TypeName, such as VSwitchService.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnServiceFabricReplica -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -ServiceTypeName 'ApiService'
    .EXAMPLE
        PS> Get-SdnServiceFabricReplica -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -ServiceName 'fabric:/NetworkController/ApiService'
    #>

    [CmdletBinding(DefaultParameterSetName = 'NamedService')]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String]$ApplicationName = 'fabric:/NetworkController',

        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [System.String]$ServiceName,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String]$ServiceTypeName,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [Switch]$Primary
    )

    $sfParams = @{
        NetworkController = $NetworkController
        Credential = $Credential
    }

    switch ($PSCmdlet.ParameterSetName) {
        'NamedService' {
            $sfParams.Add('ArgumentList', @($ApplicationName, $ServiceName))
            $sb = {
                param([string]$param1, [string]$param2)
                # check if service fabric service is running
                $serviceState = Get-Service -Name 'FabricHostSvc' -ErrorAction Stop
                if ($serviceState.Status -ne 'Running') {
                    throw New-Object System.Exception("Service Fabric Service is currently not running.")
                }

                # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
                $null = Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null
                Get-ServiceFabricApplication -ApplicationName $param1 | Get-ServiceFabricService -ServiceName $param2 | Get-ServiceFabricPartition | Get-ServiceFabricReplica
            }
        }

        'NamedServiceTypeName' {
            $sfParams.Add('ArgumentList', @($ApplicationName, $ServiceTypeName))
            $sb = {
                param([string]$param1, [string]$param2)
                # check if service fabric service is running
                $serviceState = Get-Service -Name 'FabricHostSvc' -ErrorAction Stop
                if ($serviceState.Status -ne 'Running') {
                    throw New-Object System.Exception("Service Fabric Service is currently not running.")
                }

                # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
                $null = Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null
                Get-ServiceFabricApplication -ApplicationName $param1 | Get-ServiceFabricService -ServiceTypeName $param2 | Get-ServiceFabricPartition | Get-ServiceFabricReplica
            }
        }
    }

    try {
        $replica = Invoke-SdnServiceFabricCommand @sfParams -ScriptBlock $sb

        # as network controller only leverages stateful service fabric services, we will have Primary and ActiveSecondary replicas
        # if the -Primary switch was declared, we only want to return the primary replica for that particular service
        if ($Primary) {
            return ($replica | Where-Object { $_.ReplicaRole -ieq 'Primary' })
        }
        else {
            return $replica
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnServiceFabricService {
    <#
    .SYNOPSIS
        Gets a list of Service Fabric services from Network Controller.
    .PARAMETER ApplicationName
        A service fabric application name that exists on the provided ring, such as fabric:/NetworkController.
    .PARAMETER ServiceName
        A service fabric service name that is under the provided ApplicationName on the provided ring, such as fabric:/NetworkController/ApiService.
    .PARAMETER ServiceTypeName
        A service fabric service TypeName, such as VSwitchService
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnServiceFabricService -NetworkController 'Prefix-NC01' -Credential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnServiceFabricService -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -ServiceTypeName 'ApiService'
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param(
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String]$ApplicationName = 'fabric:/NetworkController',

        [Parameter(Mandatory = $true, ParameterSetName = 'NamedService')]
        [System.String]$ServiceName,

        [Parameter(Mandatory = $true, ParameterSetName = 'NamedServiceTypeName')]
        [System.String]$ServiceTypeName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sfParams = @{
        NetworkController = $NetworkController
        Credential = $Credential
    }

    switch ($PSCmdlet.ParameterSetName) {
        'NamedService' {
            $sfParams.Add('ArgumentList',@($ApplicationName, $ServiceName))
            $sb = {
                param([string]$param1, [string]$param2)
                if (( Get-Service -Name 'FabricHostSvc').Status -ine 'Running' ) {
                    throw New-Object System.Exception("Service Fabric Service is currently not running.")
                }

                # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
                $null = Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null
                Get-ServiceFabricApplication -ApplicationName $param1 | Get-ServiceFabricService -ServiceName $param2
            }
        }
        'NamedServiceTypeName' {
            $sfParams.Add('ArgumentList',@($ApplicationName, $ServiceTypeName))
            $sb = {
                param([string]$param1, [string]$param2)
                # check if service fabric service is running
                $serviceState = Get-Service -Name 'FabricHostSvc' -ErrorAction Stop
                if ($serviceState.Status -ne 'Running') {
                    throw New-Object System.Exception("Service Fabric Service is currently not running.")
                }

                # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
                $null = Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null
                Get-ServiceFabricApplication -ApplicationName $param1 | Get-ServiceFabricService -ServiceTypeName $param2
            }
        }
        default {
            $sfParams.Add('ArgumentList',@($ApplicationName))
            $sb = {
                param([string]$param1)
                # check if service fabric service is running
                $serviceState = Get-Service -Name 'FabricHostSvc' -ErrorAction Stop
                if ($serviceState.Status -ne 'Running') {
                    throw New-Object System.Exception("Service Fabric Service is currently not running.")
                }

                # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
                $null = Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null
                Get-ServiceFabricApplication -ApplicationName $param1 | Get-ServiceFabricService
            }
        }
    }

    try {
        Invoke-SdnServiceFabricCommand @sfParams -ScriptBlock $sb
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

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

    if ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType -ine 'ServiceFabric') {
        throw New-Object System.NotSupportedException("This function is only supported on Service Fabric clusters.")
    }

    $params = @{
        ScriptBlock = $ScriptBlock
    }
    if ($ArgumentList) {
        $params.Add('ArgumentList', $ArgumentList)
    }
    if (-NOT (Test-ComputerNameIsLocal -ComputerName $NetworkController)) {
        $params.Add('ComputerName', $NetworkController)
        $params.Add('Credential', $Credential)
    }
    else {
        Confirm-IsNetworkController
    }

    "NetworkController: {0}, ScriptBlock: {1}" -f $NetworkController, $ScriptBlock.ToString() | Trace-Output -Level:Verbose
    if ($params.ArgumentList) {
        "ArgumentList: {0}" -f ($params.ArgumentList | ConvertTo-Json).ToString() | Trace-Output -Level:Verbose
    }

    $sfResults = Invoke-Command @params -ErrorAction Stop
    if ($sfResults.GetType().IsPrimitive -or ($sfResults -is [String])) {
        return $sfResults
    }
    else {
        return ($sfResults | Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId)
    }
}

function Move-SdnServiceFabricReplica {
    <#
    .SYNOPSIS
        Moves the Service Fabric primary replica of a stateful service partition on Network Controller.
    .PARAMETER ApplicationName
        A service fabric application name that exists on the provided ring, such as fabric:/NetworkController.
    .PARAMETER ServiceName
        A service fabric service name that is under the provided ApplicationName on the provided ring, such as fabric:/NetworkController/ApiService.
    .PARAMETER ServiceTypeName
        A service fabric service TypeName, such as VSwitchService.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER NodeName
        Specifies the name of a Service Fabric node. The cmdlet moves the primary replica to the node that you specify.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS > Move-SdnServiceFabricReplica -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -ServiceTypeName 'ApiService'
    #>

    [CmdletBinding(DefaultParameterSetName = 'NamedService')]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [String]$ApplicationName = 'fabric:/NetworkController',

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [String]$ServiceName,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [String]$ServiceTypeName,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String]$NodeName,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    if ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType -ine 'ServiceFabric') {
        throw New-Object System.NotSupportedException("This function is only supported on Service Fabric clusters.")
    }

    $sfParams = @{
        NetworkController = $NetworkController
        Credential = $Credential
    }
    $moveSfParams = $sfParams.Clone()

    switch ($PSCmdlet.ParameterSetName) {
        'NamedService' {
            $sfParams.Add('ServiceName', $ServiceName)
        }
        'NamedServiceTypeName' {
            $sfParams.Add('ServiceTypeName', $ServiceTypeName)
        }
    }

    $moveReplicaSB = {
        param([string]$param1, [string]$param2)
        $splat = @{
            ServiceName = $param1
        }
        if (-NOT [string]::IsNullOrEmpty($param2)) {
            $splat.Add('NodeName', $param2)
        }

        # check if service fabric service is running
        $serviceState = Get-Service -Name 'FabricHostSvc' -ErrorAction Stop
        if ($serviceState.Status -ne 'Running') {
            throw New-Object System.Exception("Service Fabric Service is currently not running.")
        }

        # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
        $null = Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null
        Move-ServiceFabricPrimaryReplica @splat
    }

    try {
        # check to determine how many replicas are part of the partition for the service
        # if we only have a single replica, then generate a warning and stop further processing
        # otherwise locate the primary replica
        $service = Get-SdnServiceFabricService @sfParams -ErrorAction Stop
        $serviceFabricReplicas = Get-SdnServiceFabricReplica @sfParams
        if ($serviceFabricReplicas.Count -lt 3) {
            "Moving Service Fabric replica is only supported when running 3 or more instances of Network Controller" | Trace-Output -Level:Warning
            return
        }

        $replicaBefore = $serviceFabricReplicas | Where-Object {$_.ReplicaRole -ieq 'Primary'}
        "Replica currently is on {0}" -f $replicaBefore.NodeName | Trace-Output -Level:Verbose

        # no useful information is returned during the move operation, so we will just null the results that are returned back
        $moveSfParams.Add('ArgumentList', @($service.ServiceName, $NodeName))
        $moveSfParams.Add('ScriptBlock', $moveReplicaSB)
        $null = Invoke-SdnServiceFabricCommand @moveSfParams

        # update the hash table to now define -Primary switch, which will be used to get the service fabric replica primary
        [void]$sfParams.Add('Primary', $true)
        $replicaAfter = Get-SdnServiceFabricReplica @sfParams
        "Replica for {0} has been moved from {1} to {2}" -f $service.ServiceName, $replicaBefore.NodeName, $replicaAfter.NodeName | Trace-Output
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function New-SdnCertificateRotationConfig {
    <#
    .SYNOPSIS
        Prepare the Network Controller Ceritifcate Rotation Configuration to determine which certificates to be used.
    .PARAMETER NetworkController
        Specifies the name the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> New-SdnCertificateRotationConfig
    .EXAMPLE
        PS> New-SdnCertificateRotationConfig -NetworkController 'NC01' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]$NetworkController = $(HostName),

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if (-NOT ($PSBoundParameters.ContainsKey('NetworkController'))) {
            $config = Get-SdnModuleConfiguration -Role 'NetworkController_SF'
            $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
            if (-NOT ($confirmFeatures)) {
                "The current machine is not a NetworkController, run this on NetworkController or use -NetworkController parameter to specify one" | Trace-Output -Level:Warning
                return # don't throw exception, since this is a controlled scenario and we do not need stack exception tracing
            }
        }

        $NcInfraInfo = Get-SdnNetworkControllerInfoOffline -NetworkController $NetworkController -Credential $Credential

        $CertificateRotationConfig = @{}
        $CertificateRotationConfig["ClusterCredentialType"] = $NcInfraInfo.ClusterCredentialType
        $getNewestCertScript = {
            param(
                [String]
                $certSubject
            )

            # Default to return Node Certificate
            if ([string]::IsNullOrEmpty($certSubject)) {
                $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName + "." + (get-ciminstance win32_computersystem).Domain
                $certSubject = "CN=$NodeFQDN"
            }

            Write-Verbose "Looking for cert match $certSubject"
            $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -ieq $certSubject } | Sort-Object -Property NotBefore -Descending | Select-Object -First 1
            return $cert.Thumbprint
        }
        $CertificateRotationConfig["NcRestCert"] = Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock $getNewestCertScript -ArgumentList "CN=$($NcInfraInfo.NcRestName)" -Credential $Credential

        if($NcInfraInfo.ClusterCredentialType -eq "X509"){
            foreach ($ncNode in $($NcInfraInfo.NodeList)) {
                Trace-Output -Message "Looking for Node Cert for Node: $($ncNode.NodeName), IpAddressOrFQDN: $($ncNode.IpAddressOrFQDN)" -Level:Verbose
                $ncNodeCert = Invoke-PSRemoteCommand -ComputerName $ncNode.IpAddressOrFQDN -ScriptBlock $getNewestCertScript -Credential $Credential
                $CertificateRotationConfig[$ncNode.NodeName.ToLower()] = $ncNodeCert
            }
        }

        return $CertificateRotationConfig
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Set-SdnNetworkController {
    <#
    .SYNOPSIS
        Sets network controller application settings.
    .PARAMETER RestIPAddress
        Specifies the IP address on which network controller nodes communicate with the REST clients. This IP address must not be an existing IP address on any of the network controller nodes.
    .PARAMETER RestName
        Switch parameter to configure the network controller application to use the server certificate's subject name as the REST endpoint name.
    .PARAMETER Credential
        Specifies a user credential that has permission to perform this action. The default is the current user.
        Specify this parameter only if you run this cmdlet on a computer that is not part of the network controller cluster.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'RestIPAddress')]
        [ValidateScript({
            $split = $_.split('/')
            if ($split.count -ne 2) { throw "RestIpAddress must be in CIDR format."}
            if (!($split[0] -as [ipaddress] -as [bool])) { throw "Invalid IP address specified in RestIpAddress."}
            if (($split[1] -le 0) -or ($split[1] -gt 32)) { throw "Invalid subnet bits specified in RestIpAddress."}
            return $true
        })]
        [System.String]$RestIpAddress,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestName')]
        [Switch]$RestName,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestIPAddress')]
        [Parameter(Mandatory = $false, ParameterSetName = 'RestName')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential
    )

    if ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType -ine 'ServiceFabric') {
        throw New-Object System.NotSupportedException("This function is only supported on Service Fabric clusters.")
    }

    Confirm-IsAdmin
    Confirm-IsNetworkController

    $waitDuration = 30 # seconds
    $params = @{}
    if ($Credential -ne [System.Management.Automation.PSCredential]::Empty -and $null -ne $Credential) {
        $params.Add('Credential', $Credential)
    }

    try {
        $getNetworkController = Get-SdnNetworkControllerSF
        if ($null -eq $getNetworkController) {
            throw New-Object System.Exception("Unable to retrieve results from Get-SdnNetworkControllerSF.")
        }

        $certSubjectName = $getNetworkController.ServerCertificate.Subject.Split('=')[1].Trim()
        if ($null -eq $certSubjectName) {
            throw New-Object System.Exception("Unable to retrieve current ServerCertificate.Subject property")
        }

        Connect-ServiceFabricCluster | Out-Null
        $param = Get-ServiceFabricApplication -ApplicationName 'fabric:/NetworkController' -ErrorAction Stop
        $version = $param.ApplicationParameters["SDNAPIConfigVersion"].Value
        $client=[System.Fabric.FabricClient]::new()

        switch ($PSCmdlet.ParameterSetName) {
            'RestName' {
                $params.Add('RestName', $certSubjectName)

                if ($getNetworkController.RestName) {
                    "Network Controller is already configured with RestName: {0}" -f $getNetworkController.RestName | Trace-Output -Level:Warning
                    return
                }

                else {
                    # if we changing from RestIPAddress to RestName, then we need to remove the RestIPAddress property and add the RestURL property
                    # once we remove the RestIPAddress property, we can perform a PUT operation to set the RestURL property
                    "Operation will set RestName to {0}." -f $certSubjectName | Trace-Output -Level:Warning
                    $confirm = Confirm-UserInput -Message "Do you want to proceed with operation? [Y/N]:"
                    if ($confirm) {
                        "Deleting the current RestIPAddress property" | Trace-Output
                        $client.PropertyManager.DeletePropertyAsync("fabric:/NetworkController/GlobalConfiguration", "SDNAPI.$version.RestIPAddress")
                        $client.PropertyManager.PutPropertyAsync("fabric:/NetworkController/GlobalConfiguration", "SDNAPI.$version.RestURL", $certSubjectName)
                    }
                    else {
                        "User has opted to abort the operation. Terminating operation" | Trace-Output
                        return
                    }
                }
            }

            'RestIPAddress' {
                $params.Add('RestIPAddress', $RestIpAddress)

                # check to see if the RestIPAddress is already configured, if so, then cross-compare the value currently configured with the new value
                # if we are just changing from one IP to another, then we can just update the value using Set-NetworkController
                if ($getNetworkController.RestIPAddress) {
                    if ($getNetworkController.RestIPAddress -ieq $RestIpAddress) {
                        "RestIPAddress is already set to {0}. Aborting operation." -f $getNetworkController.RestIPAddress | Trace-Output -Level:Warning
                        return
                    }
                    else {
                        "RestIPAddress is currently set to {0}. Operation will set RestIPAddress to {1}." -f $getNetworkController.RestIPAddress, $RestIpAddress | Trace-Output -Level:Warning
                        $confirm = Confirm-UserInput -Message "Do you want to proceed with operation? [Y/N]:"
                        if ($confirm) {
                            # do nothing here directly, since we will be calling Set-NetworkController later on
                        }
                        else {
                            "User has opted to abort the operation. Terminating operation" | Trace-Output
                            return
                        }
                    }
                }

                # if we changing from RestName to RestIPAddress, then we need to remove the RestURL property and add the RestIPAddress property
                # once we remove the RestUrl property, we need to insert a dummy CIDR value to ensure that the Set-NetworkController operation does not fail
                else {
                    "Operation will set RestIPAddress to {0}." -f $RestIpAddress | Trace-Output -Level:Warning
                    $confirm = Confirm-UserInput -Message "Do you want to proceed with operation? [Y/N]:"
                    if ($confirm) {
                        "Deleting the current RestURL property and inserting temporary RestIPAddress" | Trace-Output
                        $client.PropertyManager.DeletePropertyAsync("fabric:/NetworkController/GlobalConfiguration", "SDNAPI.$version.RestURL")
                        $client.PropertyManager.PutPropertyAsync("fabric:/NetworkController/GlobalConfiguration", "SDNAPI.$version.RestIPAddress", "10.65.15.117/27")
                    }
                    else {
                        "User has opted to abort the operation. Terminating operation" | Trace-Output
                        return
                    }
                }
            }
        }

        "Sleeping for {0} seconds" -f $waitDuration | Trace-Output
        Start-Sleep -Seconds $waitDuration # wait for the property to be deleted

        "Calling Set-NetworkController with params: {0}" -f ($params | ConvertTo-Json) | Trace-Output
        Set-NetworkController @params

        return (Get-SdnNetworkControllerSF)
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
    finally {
        if ($client) {
            $client.Dispose()
        }
    }
}

function Set-SdnServiceFabricClusterConfig {
    <#
    .SYNOPSIS
        Gets Service Fabric Cluster Config Properties.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates. Default to local machine.
    .PARAMETER Uri
        The Uri to read properties from ClusterConfiguration, GlobalConfiguration
    .PARAMETER Name
        Property Name to filter the result. If not specified, it will return all properties.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Set-SdnServiceFabricClusterConfig -NetworkController 'NC01' -Uri "ClusterConfiguration" -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]$NetworkController = $(HostName),

        [Parameter(Mandatory = $true)]
        [ValidateSet('GlobalConfiguration', 'ClusterConfiguration')]
        [String]$Uri,

        [Parameter(Mandatory = $true)]
        [String]$Name,

        [Parameter(Mandatory = $true)]
        [System.Object]$Value,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    if ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType -ine 'ServiceFabric') {
        throw New-Object System.NotSupportedException("This function is only supported on Service Fabric clusters.")
    }

    try {
        Connect-ServiceFabricCluster | Out-Null
        $client = [System.Fabric.FabricClient]::new()
        $absoluteUri = "fabric:/NetworkController/$Uri"
        $task = $client.PropertyManager.PutPropertyAsync($absoluteUri, $Name, $Value)
        $task.Wait()
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-SdnCertificateRotationConfig {
    <#
    .SYNOPSIS
        Validate the Cert Rotation Config provided is correct. Ensure certificates specified present on the machine.
    .PARAMETER NcNodeList
        The NcNodeList that retrieved via Get-SdnNetworkControllerInfoOffline.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER CertRotateConfig
        The Config generated by New-SdnCertificateRotationConfig to include NC REST certificate thumbprint and node certificate thumbprint.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$NcNodeList,

        [Parameter(Mandatory = $true)]
        [hashtable]$CertRotateConfig,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {

        if ([string]::IsNullOrEmpty($CertRotateConfig["NcRestCert"])) {
            Trace-Output -Message "NcRestCert not specified in CertRotateConfig" -Level:Error
            return $false
        }

        $ncRestCert = $CertRotateConfig["NcRestCert"]
        foreach ($ncNode in $NcNodeList) {
            if ($CertRotateConfig["ClusterCredentialType"] -ieq "X509") {
                $nodeCert = $CertRotateConfig[$ncNode.NodeName.ToLower()]
                if ([string]::IsNullOrEmpty($nodeCert)) {
                    Trace-Output -Message "The ClusterCredentialType is X509 but Node $($ncNode.NodeName) does not have certificate specified" -Level:Error
                    return $false
                }
                else {
                    $certValid = Invoke-PSRemoteCommand -ComputerName $ncNode.IpAddressOrFQDN -Credential $Credential -ScriptBlock {
                        param([Parameter(Position = 0)][String]$param1)
                        $nodeCertObj = Get-SdnCertificate -Path "Cert:\LocalMachine\My" -Thumbprint $param1
                        if ($null -eq $nodeCertObj) {
                            return $false
                        }
                        else {
                            if ($nodeCertObj.NotAfter -le (Get-Date)) {
                                return $false
                            }
                        }
                        return $true
                    } -ArgumentList $nodeCert

                    if (!$certValid) {
                        Trace-Output -Message "Node $($ncNode.NodeName) does not have validate Node certificate with thumbprint $nodeCert installed" -Level:Error
                        return $false
                    }
                }
            }

            $certValid = Invoke-PSRemoteCommand -ComputerName $ncNode.IpAddressOrFQDN -Credential $Credential -ScriptBlock {
                param([Parameter(Position = 0)][String]$param1)
                $ncRestCertObj = Get-SdnCertificate -Path "Cert:\LocalMachine\My" -Thumbprint $param1
                if ($null -eq $ncRestCertObj) {
                    return $false
                }
                else {
                    if ($ncRestCertObj.NotAfter -le (Get-Date)) {
                        return $false
                    }
                }
                return $true
            } -ArgumentList $ncRestCert

            if (!$certValid) {
                Trace-Output -Message "Node $($ncNode.NodeName) does not have validate NcRest certificate with thumbprint $ncRestCert installed" -Level:Error
                return $false
            }
        }
        return $true
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

