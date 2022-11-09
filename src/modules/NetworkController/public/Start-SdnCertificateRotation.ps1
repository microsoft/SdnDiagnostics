# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Start-SdnCertificateRotation {
    <#
    .SYNOPSIS
        Performs a controller certificate rotate operation for Network Controller Northbound API, Southbound communications and Network Controller nodes.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
	.PARAMETER CertRotateConfig
		The Config generated by New-SdnCertificateRotationConfig to include NC REST certificate thumbprint and node certificate thumbprint.      
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $false, ParameterSetName = 'SelfSigned')]
        [Parameter(Mandatory = $false, ParameterSetName = 'CertConfig')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $false, ParameterSetName = 'SelfSigned')]
        [Parameter(Mandatory = $false, ParameterSetName = 'CertRotateConfig')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Pfx')]
        [System.IO.DirectoryInfo]$CertPath,

        [Parameter(Mandatory = $false, ParameterSetName = 'SelfSigned')]
        [Switch]$GenerateCertificate,

        [Parameter(Mandatory = $true, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $true, ParameterSetName = 'SelfSigned')]
        [System.Security.SecureString]$CertPassword,

        [Parameter(Mandatory = $false, ParameterSetName = 'SelfSigned')]
        [datetime]
        $NotAfter = (Get-Date).AddYears(1),

        [Parameter(Mandatory = $true, ParameterSetName = 'CertConfig')]
        [hashtable]
        $CertRotateConfig
    )

    # ensure that the module is running as local administrator
    $elevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-NOT $elevated) {
        throw New-Object System.Exception("This function requires elevated permissions. Run PowerShell as an Administrator and import the module again.")
    }

    $config = Get-SdnRoleConfiguration -Role 'NetworkController'
    $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
    if (-NOT ($confirmFeatures)) {
        throw New-Object System.NotSupportedException("The current machine is not a NetworkController, run this on NetworkController.")
    }

    try {
        "Starting certificate rotation" | Trace-Output
        "Retrieving current SDN environment details" | Trace-Output

        # Get the Network Controller Info Offline (NC Cluster Down case)
        $NcInfraInfo = Get-SdnNetworkControllerInfoOffline -Credential $Credential
        
        if ($NcInfraInfo.ClusterCredentialType -ieq 'X509') {
            $rotateNCNodeCerts = $true
        }

        # Get the current rest certificate to determine if it is expired scenario or not. 
        $currentRestCert = Get-SdnNetworkControllerRestCertificate

        $restCertExpired = (Get-Date) -gt $($currentRestCert.NotAfter)

        if($restCertExpired){
            "Network Controller Rest Certificate $($currentRestCert.Thumbprint) expired at $($currentRestCert.NotAfter)." | Trace-Output -Level:Warning
            $sdnFabricDetails = @{
                NetworkController = $NcInfraInfo.NodeList.IpAddressOrFQDN
            }

            Install-SdnDiagnostics -ComputerName $sdnFabricDetails.NetworkController -ErrorAction Stop
        }
        else{
            # determine fabric information and current version settings for network controller
            $sdnFabricDetails = Get-SdnInfrastructureInfo -NetworkController $env:COMPUTERNAME -Credential $Credential -NcRestCredential $NcRestCredential
            $ncClusterSettings = Get-NetworkControllerCluster
            $ncSettings = @{
                NetworkControllerVersion        = (Get-NetworkController).Version
                NetworkControllerClusterVersion = $ncClusterSettings.Version
                ClusterAuthentication = $ncClusterSettings.ClusterAuthentication
            }

            # before we proceed with anything else, we want to make sure that all the Network Controllers within the SDN fabric are running the current version
            Install-SdnDiagnostics -ComputerName $sdnFabricDetails.NetworkController -ErrorAction Stop

            if($null -ne $sdnFabricDetails.SoftwareLoadBalancer){
                Install-SdnDiagnostics -ComputerName $sdnFabricDetails.SoftwareLoadBalancer -ErrorAction Stop
            }

            if($null -ne $sdnFabricDetails.Server){
                Install-SdnDiagnostics -ComputerName $sdnFabricDetails.Server -ErrorAction Stop
            }

            Remove-PSRemotingSession -ComputerName $sdnFabricDetails.FabricNodes

            "Network Controller version: {0}" -f $ncSettings.NetworkControllerVersion | Trace-Output
            "Network Controller cluster version: {0}" -f $ncSettings.NetworkControllerClusterVersion | Trace-Output

            $healthState = Get-SdnServiceFabricClusterHealth -NetworkController $env:COMPUTERNAME
            if ($healthState.AggregatedHealthState -ine 'Ok') {
                "Service Fabric AggregatedHealthState is currently reporting {0}. Please address underlying health before proceeding with certificate rotation" `
                -f $healthState.AggregatedHealthState | Trace-Output -Level:Exception
                $confirm = Confirm-UserInput -Message "Enter N to abort and address the underlying health. Enter Y to force continue: "
                if (-NOT $confirm){
                    "User has opted to abort the operation. Terminating operation" | Trace-Output -Level:Warning
                    return
                }
            }
        }

        #####################################
        #
        # Create Certificate (Optional)
        #
        #####################################

        if ($GenerateCertificate) {
            "== STAGE: CREATE SELF SIGNED CERTIFICATES ==" | Trace-Output

            $certGenerationInfo = New-SdnNetworkControllerCertificate -NetworkControllers $sdnFabricDetails.NetworkController -GenerateNcNodeCertificate:$rotateNCNodeCerts -NcRestName $NcInfraInfo.NcRestName `
                -NotAfter $NotAfter -CertPassword $CertPassword  -Credential $Credential
            $CertPath = $certGenerationInfo.CertPath
        }

        #####################################
        #
        # Certificate Seeding
        #
        #####################################

        if ($PSBoundParameters.ContainsKey('GenerateCertificate') -or $PSBoundParameters.ContainsKey('CertPath')) {
            "== STAGE: CERTIFICATE SEEDING ==" | Trace-Output
            # FabricDetails include NetworkController's ServerName (FQDN), returned CertificateConfig use ServerName as the key to map node certificate
            $certificateInstalled = Copy-CertificatesToFabric -CertPath $CertPath -CertPassword $CertPassword -FabricDetails $sdnFabricDetails -RotateNodeCertificates:$rotateNCNodeCerts

            "Installed Certificate:" | Trace-Output
            "NcRestCert: $($certificateInstalled.RestCert)" | Trace-Output
            # CertRotateConfig use NetworkController's NodeName as the key to map node certificate
            $CertRotateConfig = @{}
            $CertRotateConfig["NcRestCert"] = $certificateInstalled.RestCert
            $certRotateConfig["ClusterCredentialType"] = $NcInfraInfo.ClusterCredentialType

            if($certRotateConfig["ClusterCredentialType"] -ieq "X509"){
                foreach($ncnode in $NcInfraInfo.NodeList){
                    $nodeCert = $certificateInstalled.NetworkController[$ncnode.IpAddressOrFQDN].Cert.PfxData.EndEntityCertificates.Thumbprint
                    "$($ncnode.IpAddressOrFQDN)'s NodeCert: $nodeCert" | Trace-Output
                    if($null -eq $nodeCert){
                        throw New-Object System.NullReferenceException("Unable to locate node certificate for $($ncnode.IpAddressOrFQDN) after installed")
                    }
                    $certRotateConfig[$ncnode.NodeName.ToLower()] = $nodeCert
                }
            }
        }

        #####################################
        #
        # Certificate Configuration
        #
        #####################################

        "== STAGE: DETERMINE CERTIFICATE CONFIG ==" | Trace-Output

        "Validating Certificate Configuration" | Trace-Output
        $certValidated = Test-SdnCertificateRotationConfig -NcNodeList $NcInfraInfo.NodeList -CertRotateConfig $CertRotateConfig -Credential $Credential

        if($certValidated -ne $true){
            throw New-Object System.NotSupportedException("Unable to validate certificate configuration")
        }

        $updatedRestCertificate = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -ieq $currentRestCert.Subject} `
        | Sort-Object -Property NotBefore -Descending | Select-Object -First 1

        "Network Controller Rest Certificate {0} will be updated from [Thumbprint:{1} NotAfter:{2}] to [Thumbprint:{3} NotAfter:{4}]" `
        -f $currentRestCert.Subject, $currentRestCert.Thumbprint, $currentRestCert.NotAfter, $CertRotateConfig["NcRestCert"], $updatedRestCertificate.NotAfter `
        | Trace-Output -Level:Warning

        if ($rotateNCNodeCerts) {
            foreach ($node in $NcInfraInfo.NodeList){
                $nodeCertThumbprint = $certRotateConfig[$node.NodeName.ToLower()]
                $newNodeCert = Get-Item "Cert:LocalMachine\My\$nodeCertThumbprint"
                $currentNodeCert = Invoke-PSRemoteCommand -ComputerName $node.IpAddressOrFQDN -Credential $Credential -ScriptBlock {
                    Get-SdnNetworkControllerNodeCertificate
                }
                "Network Controller Node Certificate {0} will be updated from [Thumbprint:{1} NotAfter:{2}] to [Thumbprint:{3} NotAfter:{4}]" `
                    -f $currentNodeCert.Subject, $currentNodeCert.Thumbprint, $currentNodeCert.NotAfter, `
                    $nodeCertThumbprint, $newNodeCert.NotAfter | Trace-Output -Level:Warning
            }    
        }
        
        $confirm = Confirm-UserInput
        if (-NOT $confirm){
            "User has opted to abort the operation. Terminating operation" | Trace-Output -Level:Warning
            return
        }

        #####################################
        #
        # Rotate NC Certificate Expired
        #
        #####################################

        if($restCertExpired){
            Start-SdnNetworkControllerCertificateUpdate -CertRotateConfig $CertRotateConfig -Credential $Credential -NcRestCredential $NcRestCredential
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

            foreach ($node in $NcInfraInfo.NodeList){
                $nodeCertThumbprint = $certRotateConfig[$node.NodeName.ToLower()]
                $null = Invoke-CertRotateCommand -Command 'Set-NetworkControllerNode' -NetworkController $node.IpAddressOrFQDN -Credential $Credential -Thumbprint $nodeCertThumbprint

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

        $null = Update-NetworkControllerCredentialResource -NcUri "https://$($NcInfraInfo.NcRestName)" -Credential $NcRestCredential `
        -NewRestCertThumbprint $CertRotateConfig["NcRestCert"] -ErrorAction Stop

        "Certificate rotation completed successfully" | Trace-Output
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
