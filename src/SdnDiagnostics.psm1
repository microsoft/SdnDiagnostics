# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

New-Variable -Name 'SdnDiagnostics' -Scope 'Global' -Force -Value @{
    Cache = @{}
    EnvironmentInfo = @{
        # defines the cluster configuration type, supported values are 'ServiceFabric', 'FailoverCluster'
        ClusterConfigType = 'ServiceFabric'
        FailoverClusterConfig = @{
            Name = $null
        }

        RestApiVersion = 'V1' # defaults to v1 on module load, and updated once environment details have been retrieved
        NcUrl = $null
        Gateway = @()
        NetworkController = @()
        LoadBalancerMux = @()
        Server = @()
        FabricNodes = @()
    }
    Config = @{
        # when creating remote sessions, the module will be imported automatically
        ImportModuleOnRemoteSession = $false

        # determines from a global perspective if we should be disabling automatic seeding of module to remote nodes
        DisableModuleSeeding = $false

        # by default will just leverage the name of the module, however if using custom path not under default module directory
        # can update this to be the full path name to module, which will be used on PSRemoteSessions
        ModuleName = 'SdnDiagnostics'

        # defines if this module is running on Windows Server, Azure Stack HCI or Azure Stack Hub
        # supported values are 'WindowsServer', 'AzureStackHCI', 'AzureStackHub'
        Mode = "WindowsServer"

        # defines the current role(s) determined for the current node
        # supported values are 'Common', 'Gateway', 'NetworkController', 'Server', 'LoadBalancerMux'
        Role = @()
    }
}

# in some instances where powershell has been left open for a long time, we can leave behind sessions that are no longer valid
# so we will want to clean up any SDN related sessions on module import
Remove-PSRemotingSession

$Global:SdnDiagnostics.Config.Mode = (Get-EnvironmentMode)
$Global:SdnDiagnostics.Config.Role = (Get-EnvironmentRole)

# check to see if the module is running on FC cluster
if (Confirm-IsFailoverClusterNC) {
    $Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType = 'FailoverCluster'
}

# in Azure Local environment, the NetworkControllerFc module is not available in the default
# powershell module paths. We need to import the module from the artifact path
 if ($Global:SdnDiagnostics.Config.Mode -ieq 'AzureStackHCI' -and $Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType -ieq 'FailoverCluster') {
    if ($null -ieq (Get-Module -Name 'NetworkControllerFc')) {
          try {
            $nugetPath = Get-NugetArtifactPath -NugetName 'Microsoft.AS.Network.Deploy.NC'
            Import-Module "$nugetPath\content\Powershell\Roles\NC\NetworkControllerFc" -Global
        }
        catch {
            Write-Warning "Failed to import NetworkControllerFc module. Error: $_"
        }
    }
}

##########################
#### CLASSES & ENUMS #####
##########################

##########################
#### ARG COMPLETERS ######
##########################

$argScriptBlock = @{
    AllFabricNodes = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $computerName = $Global:SdnDiagnostics.EnvironmentInfo.FabricNodes

        if ([string]::IsNullOrEmpty($wordToComplete)) {
            return ($computerName | Sort-Object)
        }

        return $computerName | Where-Object {$_ -like "*$wordToComplete*"} | Sort-Object
    }

    GatewayNodes = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $computerName = $Global:SdnDiagnostics.EnvironmentInfo.Gateway

        if ([string]::IsNullOrEmpty($wordToComplete)) {
            return ($computerName | Sort-Object)
        }

        return $computerName | Where-Object {$_ -like "*$wordToComplete*"} | Sort-Object
    }

    NetworkControllerNodes = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $computerName = $Global:SdnDiagnostics.EnvironmentInfo.NetworkController

        if ([string]::IsNullOrEmpty($wordToComplete)) {
            return ($computerName | Sort-Object)
        }

        return $computerName | Where-Object {$_ -like "*$wordToComplete*"} | Sort-Object
    }

    ServerNodes = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $computerName = $Global:SdnDiagnostics.EnvironmentInfo.Server

        if ([string]::IsNullOrEmpty($wordToComplete)) {
            return ($computerName | Sort-Object)
        }

        return $computerName | Where-Object {$_ -like "*$wordToComplete*"} | Sort-Object
    }

    LoadBalancerMuxNodes = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $computerName = $Global:SdnDiagnostics.EnvironmentInfo.LoadBalancerMux

        if ([string]::IsNullOrEmpty($wordToComplete)) {
            return ($computerName | Sort-Object)
        }

        return $computerName | Where-Object {$_ -like "*$wordToComplete*"} | Sort-Object
    }
}

$fabricNodeParamCommands = (
    'Invoke-SdnCommand',
    'Start-SdnDataCollection',
    'Start-SdnNetshTrace',
    'Stop-SdnNetshTrace'
)

Register-ArgumentCompleter -CommandName $fabricNodeParamCommands -ParameterName 'ComputerName' -ScriptBlock $argScriptBlock.AllFabricNodes

$networkControllerParamCommands = (
    'Debug-SdnFabricInfrastructure',
    'Start-SdnDataCollection',
    'Get-SdnNetworkController',
    'Get-SdnNetworkControllerNode',
    'Get-SdnNetworkControllerFC',
    'Get-SdnNetworkControllerFCNode',
    'Get-SdnNetworkControllerSF',
    'Get-SdnNetworkControllerSFNode',
    'Get-SdnNetworkControllerClusterInfo',
    'Get-SdnNetworkControllerState',
    'Get-SdnServiceFabricApplicationHealth',
    'Get-SdnServiceFabricClusterHealth',
    'Get-SdnServiceFabricClusterManifest',
    'Get-SdnServiceFabricNode',
    'Get-SdnServiceFabricReplica',
    'Get-SdnServiceFabricService',
    'Invoke-SdnServiceFabricCommand',
    'Move-SdnServiceFabricReplica'
)

Register-ArgumentCompleter -CommandName $networkControllerParamCommands -ParameterName 'NetworkController' -ScriptBlock $argScriptBlock.NetworkControllerNodes

$serverParamCommands = (
    'Get-SdnOvsdbAddressMapping',
    'Get-SdnOvsdbFirewallRule',
    'Get-SdnOvsdbGlobalTable',
    'Get-SdnOvsdbPhysicalPort',
    'Get-SdnOvsdbUcastMacRemoteTable',
    'Get-SdnProviderAddress',
    'Get-SdnVfpVmSwitchPort',
    'Get-SdnVMNetworkAdapter'
)

Register-ArgumentCompleter -CommandName $serverParamCommands -ParameterName 'ComputerName' -ScriptBlock $argScriptBlock.ServerNodes

##########################
####### FUNCTIONS ########
##########################

function Get-SdnConfigState {
    <#
    .SYNOPSIS
        Gets the configuration state of the computer.
    .PARAMETER Role
        The SDN role of the computer.
    .PARAMETER OutputDirectory
        The directory to output the configuration state to.
    .EXAMPLE
        PS> Get-SdnConfigState -Role Server -OutputDirectory C:\Temp
    .EXAMPLE
        PS> Get-SdnConfigState -Role NetworkController,Server -OutputDirectory C:\Temp
    #>

    [cmdletbinding()]
    param(
        [parameter(Mandatory = $false)]
        [ValidateSet('Common', 'Gateway', 'NetworkController', 'Server', 'LoadBalancerMux')]
        [String[]]$Role = $Global:SdnDiagnostics.Config.Role,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    foreach ($r in $Role) {
        switch ($r) {
            'Common' {
                Get-CommonConfigState -OutputDirectory $OutputDirectory
            }
            'Gateway' {
                Get-GatewayConfigState -OutputDirectory $OutputDirectory
            }
            'NetworkController' {
                Get-NetworkControllerConfigState -OutputDirectory $OutputDirectory
            }
            'Server' {
                Get-ServerConfigState -OutputDirectory $OutputDirectory
            }
            'LoadBalancerMux' {
                Get-SlbMuxConfigState -OutputDirectory $OutputDirectory
            }
        }
    }
}

function Start-SdnCertificateRotation {
    <#
    .SYNOPSIS
        Performs a controller certificate rotate operation for Network Controller Northbound API, Southbound communications and Network Controller nodes.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API. Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
		Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    .PARAMETER CertPath
        Path directory where certificate(s) .pfx files are located for use with certificate rotation.
    .PARAMETER GenerateCertificate
        Switch to determine if certificate rotate function should generate self-signed certificates.
    .PARAMETER CertPassword
        SecureString password for accessing the .pfx files, or if using -GenerateCertificate, what the .pfx files will be encrypted with.
    .PARAMETER NotAfter
        Expiration date when using -GenerateCertificate. If ommited, defaults to 3 years.
    .PARAMETER CertRotateConfig
        The Config generated by New-SdnCertificateRotationConfig to include NC REST certificate thumbprint and node certificate thumbprint.
    .PARAMETER Force
        Switch to force the rotation without being prompted, when Service Fabric is unhealthy.
    #>

    [CmdletBinding(DefaultParameterSetName = 'GenerateCertificate')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $true, ParameterSetName = 'GenerateCertificate')]
        [Parameter(Mandatory = $true, ParameterSetName = 'CertConfig')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Parameter(Mandatory = $false, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $false, ParameterSetName = 'GenerateCertificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'CertConfig')]
        [X509Certificate]$NcRestCertificate,

        [Parameter(Mandatory = $false, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $false, ParameterSetName = 'GenerateCertificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'CertConfig')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'Pfx')]
        [System.String]$CertPath,

        [Parameter(Mandatory = $true, ParameterSetName = 'GenerateCertificate')]
        [Switch]$GenerateCertificate,

        [Parameter(Mandatory = $true, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $true, ParameterSetName = 'GenerateCertificate')]
        [System.Security.SecureString]$CertPassword,

        [Parameter(Mandatory = $false, ParameterSetName = 'GenerateCertificate')]
        [datetime]$NotAfter = (Get-Date).AddYears(3),

        [Parameter(Mandatory = $true, ParameterSetName = 'CertConfig')]
        [hashtable]$CertRotateConfig,

        [Parameter(Mandatory = $false, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $false, ParameterSetName = 'GenerateCertificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'CertConfig')]
        [switch]$Force
    )

    $ncRestParams = @{
        NcUri = $null
    }
    if ($PSBoundParameters.ContainsKey('NcRestCertificate')) {
        $restCredParam = @{ NcRestCertificate = $NcRestCertificate }
        $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
    }
    else {
        $restCredParam = @{ NcRestCredential = $NcRestCredential }
        $ncRestParams.Add('NcRestCredential', $NcRestCredential)
    }

    # ensure that the module is running as local administrator
    Confirm-IsAdmin

    if ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType -ine 'ServiceFabric') {
        throw New-Object System.NotSupportedException("This function is only supported on Service Fabric clusters.")
    }

    $config = Get-SdnModuleConfiguration -Role 'NetworkController_SF'
    $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
    if (-NOT ($confirmFeatures)) {
        throw New-Object System.NotSupportedException("The current machine is not a NetworkController, run this on NetworkController.")
    }

    try {
        "Starting certificate rotation" | Trace-Output

        # purge any existing remote sessions to prevent situation where
        # we leverage a session without credentials
        Remove-PSRemotingSession

        "Retrieving current SDN environment details" | Trace-Output

        if ([String]::IsNullOrEmpty($CertPath)) {
            [System.String]$CertPath = "$(Get-WorkingDirectory)\Cert_{0}" -f (Get-FormattedDateTimeUTC)

            if (-NOT (Test-Path -Path $CertPath -PathType Container)) {
                $null = New-Item -Path $CertPath -ItemType Directory -Force
            }
        }

        [System.IO.FileSystemInfo]$CertPath = Get-Item -Path $CertPath -ErrorAction Stop

        # Get the Network Controller Info Offline (NC Cluster Down case)
        $NcInfraInfo = Get-SdnNetworkControllerInfoOffline -Credential $Credential
        $ncRestParams.NcUri = "https://$($NcInfraInfo.NcRestName)"
        if ($NcInfraInfo.ClusterCredentialType -ieq 'X509') {
            $rotateNCNodeCerts = $true
        }
        else {
            $rotateNCNodeCerts = $false
        }

        # Get the current rest certificate to determine if it is expired scenario or not.
        $currentRestCert = Get-SdnNetworkControllerRestCertificate
        $restCertExpired = (Get-Date) -gt $($currentRestCert.NotAfter)
        if ($restCertExpired) {
            "Network Controller Rest Certificate {0} expired at {1}" -f $currentRestCert.Thumbprint, $currentRestCert.NotAfter | Trace-Output -Level:Warning
            $isNetworkControllerHealthy = $false
        }
        else {
            $isNetworkControllerHealthy = Test-NetworkControllerIsHealthy
        }

        if ($restCertExpired -or !$isNetworkControllerHealthy) {
            $postRotateSBRestCert = $true
            $sdnFabricDetails = [SdnFabricInfrastructure]@{
                NetworkController = $NcInfraInfo.NodeList.IpAddressOrFQDN
            }

            Install-SdnDiagnostics -ComputerName $sdnFabricDetails.NetworkController -Credential $Credential -ErrorAction Stop
        }
        else {
            # determine fabric information and current version settings for network controller
            $sdnFabricDetails = Get-SdnInfrastructureInfo -NetworkController $env:COMPUTERNAME -Credential $Credential @restCredParam
            $ncClusterSettings = Get-NetworkControllerCluster
            $ncSettings = @{
                NetworkControllerVersion        = (Get-NetworkController).Version
                NetworkControllerClusterVersion = $ncClusterSettings.Version
                ClusterAuthentication           = $ncClusterSettings.ClusterAuthentication
            }

            # before we proceed with anything else, we want to make sure that all the Network Controllers within the SDN fabric are running the current version
            Install-SdnDiagnostics -ComputerName $sdnFabricDetails.NetworkController -Credential $Credential -ErrorAction Stop

            "Network Controller version: {0}" -f $ncSettings.NetworkControllerVersion | Trace-Output
            "Network Controller cluster version: {0}" -f $ncSettings.NetworkControllerClusterVersion | Trace-Output

            $healthState = Get-SdnServiceFabricClusterHealth -NetworkController $env:COMPUTERNAME -Credential $Credential
            if ($healthState.AggregatedHealthState -ine 'Ok') {
                "Service Fabric AggregatedHealthState is currently reporting {0}. Please address underlying health before proceeding with certificate rotation" `
                    -f $healthState.AggregatedHealthState | Trace-Output -Level:Error

                if (!$Force) {
                    $confirm = Confirm-UserInput -Message "Do you want to proceed with certificate rotation? Enter N to abort and address the underlying health. Enter Y to force continue:"
                    if (-NOT $confirm) {
                        "User has opted to abort the operation. Terminating operation" | Trace-Output -Level:Warning
                        return
                    }
                }
            }
        }

        #####################################
        #
        # Create Certificate (Optional)
        #
        #####################################

        if ($PSCmdlet.ParameterSetName -ieq 'GenerateCertificate') {
            "== STAGE: CREATE SELF SIGNED CERTIFICATES ==" | Trace-Output

            $newSelfSignedCert = New-SdnNetworkControllerRestCertificate -RestName $NcInfraInfo.NcRestName.ToString() -NotAfter $NotAfter -Path $CertPath.FullName `
            -CertPassword $CertPassword -Credential $Credential -FabricDetails $sdnFabricDetails

            $selfSignedRestCertFile = $newSelfSignedCert.FileInfo

            if ($rotateNCNodeCerts) {
                $null = Invoke-PSRemoteCommand -ComputerName $sdnFabricDetails.NetworkController -Credential $Credential -ScriptBlock {
                    param(
                        [Parameter(Position = 0)][DateTime]$param1,
                        [Parameter(Position = 1)][SecureString]$param2,
                        [Parameter(Position = 2)][PSCredential]$param3,
                        [Parameter(Position = 3)][String]$param4,
                        [Parameter(Position = 4)][System.Object]$param5
                    )

                    New-SdnNetworkControllerNodeCertificate -NotAfter $param1 -CertPassword $param2 -Credential $param3 -Path $param4 -FabricDetails $param5
                } -ArgumentList @($NotAfter, $CertPassword, $Credential, $CertPath.FullName, $sdnFabricDetails)
            }

            $CertRotateConfig = New-SdnCertificateRotationConfig -Credential $Credential
        }

        #####################################
        #
        # PFX Certificates (Optional)
        #
        #####################################

        if ($PSCmdlet.ParameterSetName -ieq 'Pfx') {
            "== STAGE: Install PFX Certificates to Fabric ==" | Trace-Output
            $pfxCertificates = Copy-UserProvidedCertificateToFabric -CertPath $CertPath -CertPassword $CertPassword -FabricDetails $sdnFabricDetails `
            -NetworkControllerHealthy $isNetworkControllerHealthy -Credential $Credential -RotateNodeCerts $rotateNCNodeCerts

            $pfxCertificates | ForEach-Object {
                if ($_.CertificateType -ieq 'NetworkControllerRest' ) {
                    if ($_.SelfSigned -ieq $true) {
                        $selfSignedRestCertFile = $_.FileInfo
                    }
                }
            }

            $CertRotateConfig = New-SdnCertificateRotationConfig -Credential $Credential
        }

        #####################################
        #
        # Certificate Configuration
        #
        #####################################

        "== STAGE: DETERMINE CERTIFICATE CONFIG ==" | Trace-Output

        "Validating Certificate Configuration" | Trace-Output
        $certValidated = Test-SdnCertificateRotationConfig -NcNodeList $NcInfraInfo.NodeList -CertRotateConfig $CertRotateConfig -Credential $Credential

        if ($certValidated -ne $true) {
            throw New-Object System.NotSupportedException("Unable to validate certificate configuration")
        }

        $updatedRestCertificate = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -ieq $currentRestCert.Subject } `
        | Sort-Object -Property NotBefore -Descending | Select-Object -First 1

        "Network Controller Rest Certificate {0} will be updated from [Thumbprint:{1} NotAfter:{2}] to [Thumbprint:{3} NotAfter:{4}]" `
            -f $currentRestCert.Subject, $currentRestCert.Thumbprint, $currentRestCert.NotAfter, $CertRotateConfig["NcRestCert"], $updatedRestCertificate.NotAfter `
        | Trace-Output -Level:Warning

        if ($rotateNCNodeCerts) {
            foreach ($node in $NcInfraInfo.NodeList) {
                $nodeCertThumbprint = $certRotateConfig[$node.NodeName.ToLower()]
                $currentNodeCert = Invoke-PSRemoteCommand -ComputerName $node.IpAddressOrFQDN -Credential $Credential -ScriptBlock {
                    Get-SdnNetworkControllerNodeCertificate
                }

                $newNodeCert = Invoke-PSRemoteCommand -ComputerName $node.IpAddressOrFQDN -Credential $Credential -ScriptBlock {
                    param([Parameter(Position = 0)][String]$param1, [Parameter(Position = 1)][String]$param2)
                    Get-SdnCertificate -Path $param1 -Thumbprint $param2
                } -ArgumentList @('Cert:\LocalMachine\My', $nodeCertThumbprint)

                "Network Controller Node Certificate {0} will be updated from [Thumbprint:{1} NotAfter:{2}] to [Thumbprint:{3} NotAfter:{4}]" `
                    -f $currentNodeCert.Subject, $currentNodeCert.Thumbprint, $currentNodeCert.NotAfter, `
                    $newNodeCert.Thumbprint, $newNodeCert.NotAfter | Trace-Output -Level:Warning
            }
        }

        if (!$Force) {
            $confirm = Confirm-UserInput
            if (-NOT $confirm) {
                "User has opted to abort the operation. Terminating operation" | Trace-Output -Level:Warning
                return
            }
        }

        #####################################
        #
        # Rotate NC Certificate Expired
        #
        #####################################

        if ($restCertExpired -or !$isNetworkControllerHealthy) {
            # Use this for certificate if either rest cert expired or nc unhealthy, get-networkcontroller failed
            Start-SdnExpiredCertificateRotation -CertRotateConfig $CertRotateConfig -Credential $Credential
        }

        #####################################
        #
        # Rotate NC Northbound Certificate (REST)
        #
        #####################################

        "== STAGE: ROTATE NC REST CERTIFICATE ==" | Trace-Output

        $null = Invoke-CertRotateCommand -Command 'Set-NetworkController' -Credential $Credential -Thumbprint $CertRotateConfig["NcRestCert"]

        "Waiting for 5 minutes before proceeding to the next step. Script will resume at {0}" -f (Get-Date).AddMinutes(5).ToUniversalTime().ToString() | Trace-Output
        Start-Sleep -Seconds 300

        #####################################
        #
        # Rotate Cluster Certificate
        #
        #####################################

        "== STAGE: ROTATE NC CLUSTER CERTIFICATE ==" | Trace-Output

        $null = Invoke-CertRotateCommand -Command 'Set-NetworkControllerCluster' -Credential $Credential -Thumbprint $CertRotateConfig["NcRestCert"]

        "Waiting for 5 minutes before proceeding to the next step. Script will resume at {0}" -f (Get-Date).AddMinutes(5).ToUniversalTime().ToString() | Trace-Output
        Start-Sleep -Seconds 300

        #####################################
        #
        # Rotate NC Node Certificates
        #
        #####################################

        if ($rotateNCNodeCerts) {
            "== STAGE: ROTATE NC NODE CERTIFICATE ==" | Trace-Output

            foreach ($node in $NcInfraInfo.NodeList) {
                $nodeCertThumbprint = $certRotateConfig[$node.NodeName.ToLower()]
                $null = Invoke-CertRotateCommand -Command 'Set-NetworkControllerNode' -NetworkController $node.IpAddressOrFQDN -Name $node.NodeName -Credential $Credential -Thumbprint $nodeCertThumbprint

                "Waiting for 2 minutes before proceeding to the next step. Script will resume at {0}" -f (Get-Date).AddMinutes(5).ToUniversalTime().ToString() | Trace-Output
                Start-Sleep -Seconds 120
            }
        }

        #####################################
        #
        # Rotate NC Southbound Certificates
        #
        #####################################

        "== STAGE: ROTATE SOUTHBOUND CERTIFICATE CREDENTIALS ==" | Trace-Output

        $restCertificate = Get-SdnCertificate -Path 'Cert:\LocalMachine\My' -Thumbprint $CertRotateConfig["NcRestCert"]
        $null = Update-NetworkControllerCredentialResource @ncRestParams -RestCert $restCertificate -ErrorAction Stop

        "Southbound certificate rotation completed" | Trace-Output

        #####################################
        #
        # Certificate Seeding (Southbound Nodes)
        #
        #####################################

        # if nc was unhealthy and unable to determine southbound devices in the dataplane earlier
        # we now want to check to see if nc is healthy and if we need to install the rest cert (for self-signed) to southbound devices
        if ($postRotateSBRestCert) {
            if ($selfSignedRestCertFile) {
                $sdnFabricDetails = Get-SdnInfrastructureInfo -Credential $Credential @restCredParam -Force
                $southBoundNodes = @()
                if ($null -ne $sdnFabricDetails.LoadBalancerMux) {
                    $southBoundNodes += $sdnFabricDetails.LoadBalancerMux
                }
                if ($null -ne $sdnFabricDetails.Server) {
                    $southBoundNodes += $sdnFabricDetails.Server
                }

                if ($southBoundNodes) {
                    "== STAGE: REST SELF-SIGNED CERTIFICATE SEEDING (Southbound Nodes) ==" | Trace-Output

                    # ensure that we have the latest version of sdnDiagnostics module on the southbound devices
                    Install-SdnDiagnostics -ComputerName $southBoundNodes -Credential $Credential -ErrorAction Stop

                    if ($selfSignedRestCertFile.Extension -ieq '.pfx') {
                        $cerName = $selfSignedRestCertFile.Name.Replace('.pfx', '.cer').Replace('_','.')
                        $selfSignedRestCertFile = Get-ChildItem -Path (Split-Path -Path $selfSignedRestCertFile.FullName -Parent) | Where-Object {$_.Name -ilike "*$cerName"}
                    }

                    "[REST CERT] Installing self-signed certificate to {0}" -f ($southBoundNodes -join ', ') | Trace-Output
                    [System.String]$remoteFilePath = Join-Path -Path $CertPath.FullName -ChildPath $selfSignedRestCertFile.Name
                    Invoke-PSRemoteCommand -ComputerName $southBoundNodes -Credential $Credential -ScriptBlock {
                        param($arg0)
                        if (-NOT (Test-Path -Path $arg0 -PathType Container)) {
                            $null = New-Item -Path $arg0 -ItemType Directory -Force
                        }
                    } -ArgumentList @($CertPath.FullName)

                    Copy-FileToRemoteComputer -ComputerName $southBoundNodes -Credential $Credential -Path $selfSignedRestCertFile.FullName -Destination $remoteFilePath
                    $null = Invoke-PSRemoteCommand -ComputerName $southBoundNodes -Credential $Credential -ScriptBlock {
                        param([Parameter(Position = 0)][String]$param1, [Parameter(Position = 1)][String]$param2)
                        Import-SdnCertificate -FilePath $param1 -CertStore $param2
                    } -ArgumentList @($remoteFilePath, 'Cert:\LocalMachine\Root') -ErrorAction Stop
                }
            }
        }

        #####################################
        #
        # Restart services
        #
        #####################################

        "== STAGE: RESTART NETWORK CONTROLLER SERVICES ==" | Trace-Output
        # restart the network controller services
        # this will force new TLS connections to be established to southbound devices
        # ensuring that the new certificates are used and we are able to push policies successfully

        # check to determine if we have a multi-node NC cluster and if so, leverage the SF cmdlets to move the replicas
        # otherwise, we will just stop the processes and let SF restart them automatically
        if ($sdnFabricDetails.NetworkController.Count -gt 1) {
            Move-SdnServiceFabricReplica -ServiceTypeName 'SlbManagerService'
            Move-SdnServiceFabricReplica -ServiceTypeName 'VSwitchService'
        }
        else {
            Get-Process -Name 'SDNFW' | Stop-Process -Force -ErrorAction Continue
            Get-Process -Name 'SDNSLBM' | Stop-Process -Force -ErrorAction Continue
        }

        "Certificate rotation has completed" | Trace-Output
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Start-SdnDataCollection {

    <#
    .SYNOPSIS
        Automated data collection script to pull the current configuration state in conjuction with diagnostic logs and other data points used for debugging.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER Role
        The specific SDN role(s) to collect configuration state and logs from.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER OutputDirectory
        Directory the results will be saved to. If ommitted, will default to the current working directory.
    .PARAMETER IncludeNetView
        If enabled, will execute Get-NetView on the Role(s) or ComputerName(s) defined.
    .PARAMETER IncludeLogs
        If enabled, will collect the diagnostic logs from the Role(s) or ComputerName(s) defined. Works in conjunction with the FromDate parameter.
    .PARAMETER FromDate
        Determines the start time of what logs to collect. If omitted, defaults to the last 4 hours.
    .PARAMETER ToDate
        Determines the end time of what logs to collect. Optional parameter that if ommitted, defaults to current time.
    .PARAMETER Credential
        Specifies a user account that has permission to SDN Infrastructure Nodes. The default is the current user.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API. Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    .PARAMETER Limit
        Used in conjuction with the Role parameter to limit how many nodes per role operations are performed against. If ommitted, defaults to 16.
    .PARAMETER ConvertETW
        Optional parameter that allows you to specify if .etl trace should be converted. By default, set to $true
    .EXAMPLE
        PS> Start-SdnDataCollection -NetworkController 'Contoso-NC01' -Role Gateway,NetworkController,Server,LoadBalancerMux
    .EXAMPLE
        PS> Start-SdnDataCollection -NetworkController 'Contoso-NC01' -Role Gateway,NetworkController,Server,LoadBalancerMux -IncludeLogs
    .EXAMPLE
        PS> Start-SdnDataCollection -NetworkController 'Contoso-NC01' -Role Gateway,Server,LoadBalancerMux -IncludeLogs -FromDate (Get-Date).AddHours(-1) -Credential (Get-Credential)
    .EXAMPLE
        PS> Start-SdnDataCollection -NetworkController 'Contoso-NC01' -Role LoadBalancerMux -IncludeLogs -IncludeNetView -FromDate '2023-08-11 10:00:00 AM' -ToDate '2023-08-11 11:30:00 AM'
    #>

    [CmdletBinding(DefaultParameterSetName = 'Role')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Computer')]
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Computer')]
        [ValidateScript({
            if ($_.Scheme -ne "http" -and $_.Scheme -ne "https") {
                throw New-Object System.FormatException("Parameter is expected to be in http:// or https:// format.")
            }
            return $true
        })]
        [Uri]$NcUri,

        [Parameter(Mandatory = $true, ParameterSetName = 'Role')]
        [ValidateSet('Gateway', 'NetworkController', 'Server', 'LoadBalancerMux')]
        [String[]]$Role,

        [Parameter(Mandatory = $true, ParameterSetName = 'Computer')]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Computer')]
        [System.IO.FileInfo]$OutputDirectory = (Get-WorkingDirectory),

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Computer')]
        [Switch]$IncludeNetView,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Computer')]
        [Switch]$IncludeLogs,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Computer')]
        [DateTime]$FromDate = (Get-Date).AddHours(-4),

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Computer')]
        [DateTime]$ToDate = (Get-Date),

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Computer')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Computer')]
        [X509Certificate]$NcRestCertificate,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Computer')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Int]$Limit = 16,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Computer')]
        [bool]$ConvertETW = $true
    )

    $ErrorActionPreference = 'Continue'
    $dataCollectionNodes = [System.Collections.ArrayList]::new() # need an arrayList so we can remove objects from this list

    $ncRestParams = @{}
    if ($PSBoundParameters.ContainsKey('NcUri')) {
        $ncRestParams.Add('NcUri', $NcUri)
    }
    if ($PSBoundParameters.ContainsKey('NcRestCertificate')) {
        $restCredParam = @{ NcRestCertificate = $NcRestCertificate }
        $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
    }
    else {
        $restCredParam = @{ NcRestCredential = $NcRestCredential }
        $ncRestParams.Add('NcRestCredential', $NcRestCredential)
    }

    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

    $dataCollectionObject = [PSCustomObject]@{
        DurationInMinutes = $null
        TotalSize         = $null
        OutputDirectory   = $null
        Role              = $null
        ComputerName      = @()
        IncludeNetView    = $IncludeNetView
        IncludeLogs       = $IncludeLogs
        FromDate          = $FromDate.ToString()
        FromDateUTC       = $FromDate.ToUniversalTime().ToString()
        ToDate            = $ToDate.ToString()
        ToDateUTC         = $ToDate.ToUniversalTime().ToString()
        Result            = $null
    }

    $collectLogSB = {
        param([string[]]$arg0,[String]$arg1,[DateTime]$arg2,[DateTime]$arg3,[Boolean]$arg4,[Boolean]$arg5,[string[]]$arg6)
        Get-SdnDiagnosticLogFile -LogDir $arg0 -OutputDirectory $arg1 -FromDate $arg2 -ToDate $arg3 -ConvertETW $arg4 -CleanUpFiles $arg5 -FolderNameFilter $arg6
    }

    $collectSdnLogSB = {
        param([string]$arg0,[DateTime]$arg1,[DateTime]$arg2,[Boolean]$arg3)
        Get-SdnLogFile -OutputDirectory $arg0 -FromDate $arg1 -ToDate $arg2 -ConvertETW $arg3
    }

    $collectConfigStateSB = {
        param([Parameter(Position = 0)][String]$OutputDirectory)
        Get-SdnConfigState -OutputDirectory $OutputDirectory
    }

    $collectNetViewSB = {
        param([Parameter(Position = 0)][String]$OutputDirectory)
        try {
            Invoke-SdnGetNetView -OutputDirectory $OutputDirectory -SkipAdminCheck -SkipNetshTrace -SkipVM -SkipCounters -ErrorAction Continue
        }
        catch {
            $_.Exception.Message | Write-Warning
        }
    }

    if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
        Confirm-IsNetworkController
    }

    try {
        [System.String]$childPath = 'SdnDataCollection_{0}' -f (Get-FormattedDateTimeUTC)
        [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath $childPath
        [System.IO.FileInfo]$workingDirectory = (Get-WorkingDirectory)
        [System.IO.FileInfo]$tempDirectory = "$(Get-WorkingDirectory)\Temp"

        # setup the directory location where files will be saved to
        "Starting SDN Data Collection" | Trace-Output

        if ($IncludeLogs) {
            $minGB = 10
        }
        else {
            $minGB = 5
        }

        if (-NOT (Initialize-DataCollection -FilePath $OutputDirectory.FullName -MinimumGB $minGB)) {
            "Unable to initialize environment for data collection" | Trace-Output -Level:Error
            return
        }

        "Results will be saved to {0}" -f $OutputDirectory.FullName | Trace-Output

        # generate a mapping of the environment
        $sdnFabricDetails = Get-SdnInfrastructureInfo -NetworkController $NetworkController -Credential $Credential @ncRestParams
        $sdnFabricDetails | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnInfrastructureInfo'

        # determine if network controller is using default logging mechanism to local devices or network share
        if ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType -ieq 'ServiceFabric') {
            [xml]$clusterManifest = Get-SdnServiceFabricClusterManifest -NetworkController $NetworkController -Credential $Credential
            $fileShareWinFabEtw = $clusterManifest.ClusterManifest.FabricSettings.Section | Where-Object {$_.Name -ieq 'FileShareWinFabEtw'}
            $connectionString = $fileShareWinFabEtw.Parameter | Where-Object {$_.Name -ieq 'StoreConnectionString'}
            if ($connectionString.value) {
                # typically the network share will be in a format of file://share/path
                $diagLogNetShare = ($connectionString.value).Split(':')[1].Replace('/', '\').Trim()
                $ncNodeFolders = @()
            }
        }

        switch ($PSCmdlet.ParameterSetName) {
            'Role' {
                foreach ($value in $Role) {
                    $array = @()
                    foreach ($node in $sdnFabricDetails[$value.ToString()]) {
                        $array += [PSCustomObject]@{
                            Role = $value
                            Name = (Get-ComputerNameFQDNandNetBIOS -ComputerName $node).ComputerNameNetBIOS
                        }
                    }

                    # if we have more than the limit, we will only collect data from the first $Limit nodes
                    if ($array.Count -gt $Limit) {
                        "Exceeded node limit for role {0}. Limiting nodes to the first {1} nodes" -f $value, $Limit | Trace-Output -Level:Warning
                        $array = $array | Select-Object -First $Limit

                        foreach ($object in $array) {
                            "{0} with role {1} added to data collection" -f $object.Name, $object.Role | Trace-Output
                            [void]$dataCollectionNodes.Add($object)
                        }

                    }
                    else {
                        foreach ($object in $array) {
                            "{0} with role {1} added to data collection" -f $object.Name, $object.Role | Trace-Output
                            [void]$dataCollectionNodes.Add($object)
                        }
                    }
                }
            }

            'Computer' {
                foreach ($computer in $ComputerName) {
                    $computerRole = Get-SdnRole -ComputerName $computer -EnvironmentInfo $sdnFabricDetails
                    if ($computerRole) {
                        $object = [PSCustomObject]@{
                            Role = $computerRole
                            Name = (Get-ComputerNameFQDNandNetBIOS -ComputerName $computer).ComputerNameNetBIOS
                        }

                        "{0} with role {1} added to data collection" -f $object.Name, $object.Role | Trace-Output
                        [void]$dataCollectionNodes.Add($object)
                    }
                }
            }
        }

        if ($dataCollectionNodes.Count -eq 0) {
            throw New-Object System.NullReferenceException("No data nodes identified")
        }

        # once we have identified the nodes, we need to validate WinRM connectivity to the nodes
        # if we are running on PowerShell 7 or greater, we can leverage the -Parallel parameter
        # to speed up the process
        # if we are running on PowerShell 5.1, we will need to run the process in serial
        # if we have any nodes that fail the WinRM connectivity test, we will remove them from the data collection
        "Validating WinRM connectivity to {0}" -f ($dataCollectionNodes.Name -join ', ') | Trace-Output

        $Global:ProgressPreference = 'SilentlyContinue'
        $nodesToRemove = [System.Collections.ArrayList]::new()
        $tncScriptBlock = {
            $tncResult = Test-NetConnection -ComputerName $_.Name -Port 5985 -InformationLevel Quiet
            if (-NOT ($tncResult)) {
                [void]$nodesToRemove.Add($_)
            }
        }

        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $dataCollectionNodes | Foreach-Object -ThrottleLimit 10 -Parallel $tncScriptBlock
        }
        else {
            $dataCollectionNodes | ForEach-Object $tncScriptBlock
        }

        if ($nodesToRemove.Count -gt 0) {
            foreach ($node in $nodesToRemove) {
                "{0} with role {1} removed from data collection due to WinRM connectivity issues" -f $node.Name, $node.Role | Trace-Output -Level:Warning
                $dataCollectionNodes = $dataCollectionNodes | Where-Object { $_.Name -ne $node.Name }
            }
        }
        $Global:ProgressPreference = 'Continue'

        $groupedObjectsByRole = $dataCollectionNodes | Group-Object -Property Role

        # ensure SdnDiagnostics installed across the data nodes and versions are the same
        # depending on the state of the environment though, these may result in failure
        Install-SdnDiagnostics -ComputerName $NetworkController -ErrorAction Continue
        Install-SdnDiagnostics -ComputerName $dataCollectionNodes.Name -ErrorAction Continue

        # ensure that the NcUrl is populated before we start collecting data
        # in scenarios where certificate is not trusted or expired, we will not be able to collect data
        if (-NOT ([System.String]::IsNullOrEmpty($sdnFabricDetails.NcUrl))) {
            if (-NOT ($ncRestParams.ContainsKey('NcUri'))) {
                $ncRestParams.Add('NcUri', $sdnFabricDetails.NcUrl)
            }

            $slbStateInfo = Get-SdnSlbStateInformation @ncRestParams
            $slbStateInfo | ConvertTo-Json -Depth 100 | Out-File "$($OutputDirectory.FullName)\SlbState.Json"
            Invoke-SdnResourceDump @ncRestParams -OutputDirectory $OutputDirectory.FullName
            Get-SdnNetworkControllerState -NetworkController $NetworkController -OutputDirectory $OutputDirectory.FullName -Credential $Credential @restCredParam
        }

        Get-SdnNetworkControllerClusterInfo -NetworkController $NetworkController -OutputDirectory $OutputDirectory.FullName -Credential $Credential
        $debugInfraHealthResults = Get-SdnFabricInfrastructureResult
        if ($debugInfraHealthResults) {
            $debugInfraHealthResults | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnFabricInfrastructureResult_Summary' -FileType 'txt' -Format 'table'
            $debugInfraHealthResults | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnFabricInfrastructureResult' -FileType json -Depth 5
        }

        # enumerate through each role and collect appropriate data
        "Performing cleanup of {0} directory" -f $tempDirectory.FullName | Trace-Output
        Clear-SdnWorkingDirectory -ComputerName $dataCollectionNodes.Name -Credential $Credential -Path $tempDirectory.FullName -Recurse

        "Collect configuration state details" | Trace-Output
        $splat = @{
            ComputerName     = $dataCollectionNodes.Name
            Credential       = $Credential
            ScriptBlock      = $collectConfigStateSB
            ArgumentList     = @($tempDirectory.FullName)
            AsJob            = $true
            PassThru         = $true
            ExecutionTimeout = 1800 # 30 minutes
            Activity         = "Collect Configuration State"
        }
        Invoke-PSRemoteCommand @splat

        "Checking for any previous network traces and moving them into {0}" -f $tempDirectory.FullName | Trace-Output
        $splat = @{
            ComputerName = $dataCollectionNodes.Name
            Credential   = $Credential
            ScriptBlock  = $collectLogSB
            ArgumentList = @("$($workingDirectory.FullName)\NetworkTraces", $tempDirectory.FullName, $FromDate, $ToDate, $ConvertETW, $true)
            AsJob        = $true
            PassThru     = $true
            Activity     = 'Collect Network Traces'
        }
        Invoke-PSRemoteCommand @splat

        if ($IncludeNetView) {
            "Collecting Get-NetView" | Trace-Output
            $splat = @{
                ComputerName     = $dataCollectionNodes.Name
                Credential       = $Credential
                ScriptBlock      = $collectNetViewSB
                ArgumentList     = @($tempDirectory.FullName)
                AsJob            = $true
                PassThru         = $true
                ExecutionTimeout = 1800 # 30 minutes
                Activity         = 'Collect Get-NetView'
            }
            $null = Invoke-PSRemoteCommand @splat
        }

        if ($IncludeLogs) {
            # if the system is not using a network share, we will collect the logs from the local devices
            if (!$diagLogNetShare) {
                "Collect diagnostic and event logs" | Trace-Output
                $outputDir = Join-Path -Path $tempDirectory.FullName -ChildPath 'SdnDiagnosticLogs'
                $splat = @{
                    ComputerName = $dataCollectionNodes.Name
                    Credential   = $Credential
                    ScriptBlock  = $collectSdnLogSB
                    ArgumentList = @($tempDirectory.FullName, $FromDate, $ToDate, $ConvertETW)
                    AsJob        = $true
                    PassThru     = $true
                    Activity     = 'Collect Diagnostic and Event Log Files'
                }
                Invoke-PSRemoteCommand @splat

                # check to see if audit logs are enabled
                # if so, pick them up from computers with the server role if they have been defined
                $auditEnabled = Get-SdnAuditLogSetting @ncRestParams
                $serverNodes = $dataCollectionNodes | Where-Object {$_.Role -ieq 'Server'}
                if ($serverNodes -and $auditEnabled.Enabled -eq $true) {
                    "Collect NSG audit logs" | Trace-Output
                    $auditLogOutDir = Join-Path -Path $tempDirectory.FullName -ChildPath 'AuditLogs'
                    $splat = @{
                        ComputerName = $serverNodes.Name
                        Credential   = $Credential
                        ScriptBlock  = $collectLogSB
                        ArgumentList = @($auditEnabled.Path, $auditLogOutDir, $FromDate, $ToDate)
                        AsJob        = $true
                        PassThru     = $true
                        Activity     = "Collect NSG Audit Logs"
                    }
                    Invoke-PSRemoteCommand @splat
                }
            }

            # if we are using a network share, we need to copy the logs from the network share to the output directory
            if ($diagLogNetShare) {
                $commonConfig = Get-SdnModuleConfiguration -Role:Common

                $ncNodes = $dataCollectionNodes | Where-Object {$_.Role -ieq 'NetworkController'}
                if ($ncNodes) {
                    $ncNodeFolders += $ncNodes.Name
                }

                $isNetShareMapped = New-SdnDiagNetworkMappedShare -NetworkSharePath $diagLogNetShare -Credential $Credential
                if ($isNetShareMapped) {
                    $outputDir = Join-Path -Path $OutputDirectory.FullName -ChildPath 'NetShare_SdnDiagnosticLogs'

                    # create an array of names that we will use to filter the logs
                    # this ensures that we will only pick up the logs from the nodes that we are collecting from
                    $filterArray = @()
                    $dataCollectionNodes.Name | ForEach-Object {
                        $filterArray += (Get-ComputerNameFQDNandNetBIOS -ComputerName $_).ComputerNameNetBIOS
                    }
                    $filterArray = $filterArray | Sort-Object -Unique

                    # create an array of folders to collect the logs from leveraging the common configuration
                    $logDir = @()
                    $commonConfig.DefaultLogFolders | ForEach-Object {
                        $logDir += Join-Path -Path $diagLogNetShare -ChildPath $_
                    }
                    $ncNodeFolders | ForEach-Object {
                        $ncNetBiosName = (Get-ComputerNameFQDNandNetBIOS -ComputerName $_).ComputerNameNetBIOS
                        $logDir += Join-Path -Path $diagLogNetShare -ChildPath $ncNetBiosName
                    }
                    $logDir = $logDir | Sort-Object -Unique

                    # create parameters for the Get-SdnDiagnosticLogFile function
                    $netDiagLogShareParams = @{
                        LogDir           = $logDir
                        OutputDirectory  = $outputDir
                        FromDate         = $FromDate
                        ToDate           = $ToDate
                        FolderNameFilter = $filterArray
                    }

                    Get-SdnDiagnosticLogFile @netDiagLogShareParams
                }
            }
        }

        foreach ($node in $dataCollectionNodes.Name) {
            [System.IO.FileInfo]$formattedDirectoryName = Join-Path -Path $OutputDirectory.FullName -ChildPath $node.ToLower()
            Copy-FileFromRemoteComputer -Path $tempDirectory.FullName -Destination $formattedDirectoryName.FullName -ComputerName $node -Credential $Credential -Recurse -Force
        }

        $dataCollectionObject.TotalSize = (Get-FolderSize -Path $OutputDirectory.FullName -Total)
        $dataCollectionObject.OutputDirectory = $OutputDirectory.FullName
        $dataCollectionObject.Role = $groupedObjectsByRole.Name
        $dataCollectionObject.ComputerName = $dataCollectionNodes.Name
        $dataCollectionObject.Result = 'Success'
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
        $dataCollectionObject.Result = 'Failed'
    }
    finally {
        $stopWatch.Stop()
        $dataCollectionObject.DurationInMinutes = $stopWatch.Elapsed.TotalMinutes

        try {
            "Performing post operations and cleanup of {0} across the SDN fabric" -f $tempDirectory.FullName | Trace-Output

            # check for any failed PS remoting jobs and copy them to data collection
            if (Test-Path -Path "$(Get-WorkingDirectory)\PSRemoteJob_Failures") {
                Copy-Item -Path "$(Get-WorkingDirectory)\PSRemoteJob_Failures" -Destination $formattedDirectoryName.FullName -Recurse
            }

            if ($dataCollectionNodes) {
                Clear-SdnWorkingDirectory -ComputerName $dataCollectionNodes.Name -Credential $Credential -Path $tempDirectory.FullName -Recurse
            }

            # remove any completed or failed jobs
            Remove-SdnDiagnosticJob -State @('Completed', 'Failed')
        }
        catch {
            $_ | Trace-Exception
            Write-Error -Message "An error occurred during cleanup of the SDN fabric." -Exception $_.Exception
            $dataCollectionObject.Result = 'Failed'
        }
    }

    $dataCollectionObject | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'SdnDataCollection_Summary' -FileType json -Depth 4 -ErrorAction Continue

    # we will return the object to the caller regardless if the data collection was successful or not
    $msg = "Sdn Data Collection completed with status of {0}" -f $dataCollectionObject.Result
    switch ($dataCollectionObject.Result) {
        'Success' {
            $msg | Trace-Output
        }
        'Failed' {
            $msg | Trace-Output -Level:Error
        }
    }

    return $dataCollectionObject
}

function Get-SdnLogFile {
    <#
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .PARAMETER FromDate
        Determines the start time of what logs to collect. If omitted, defaults to the last 4 hours.
    .PARAMETER ToDate
        Determines the end time of what logs to collect. Optional parameter that if ommitted, defaults to current time.
    .PARAMETER ConvertETW
        Optional parameter that allows you to specify if .etl trace should be converted. By default, set to $true
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [DateTime]$FromDate = (Get-Date).AddHours(-4),

        [Parameter(Mandatory = $false)]
        [DateTime]$ToDate = (Get-Date),

        [Parameter(Mandatory = $false)]
        [bool]$ConvertETW = $true
    )

    try {
        foreach ($r in $Global:SdnDiagnostics.Config.Role) {
            $moduleConfig = Get-SdnModuleConfiguration -Role $r
            $outputDir = Join-Path -Path $OutputDirectory.FullName -ChildPath "LogFiles\$r"

            Get-SdnEventLog -OutputDirectory $OutputDirectory.FullName -Role $r -FromDate $FromDate -ToDate $ToDate

            switch ($r) {
                'Common' {
                    Get-SdnDiagnosticLogFile -LogDir $moduleConfig.DefaultLogDirectory -OutputDirectory $outputDir -FromDate $FromDate -ToDate $ToDate -ConvertETW $ConvertETW
                }

                'NetworkController' {
                    switch ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType) {
                        'FailoverCluster' {
                            # nothing to do here currently
                        }
                        'ServiceFabric' {
                            $ncConfig = Get-SdnModuleConfiguration -Role 'NetworkController_SF'
                            [string[]]$sfLogDir = $ncConfig.Properties.CommonPaths.serviceFabricLogDirectory

                            Get-SdnDiagnosticLogFile -LogDir $sfLogDir -OutputDirectory (Join-Path -Path $outputDir -ChildPath 'ServiceFabricLogs') -FromDate $FromDate -ToDate $ToDate
                        }
                    }
                }
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

