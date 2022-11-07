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
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $false, ParameterSetName = 'SelfSigned')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $false, ParameterSetName = 'SelfSigned')]
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
        $NotAfter = (Get-Date).AddYears(1)
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
        
        # determine fabric information and current version settings for network controller
        $sdnFabricDetails = Get-SdnInfrastructureInfo -NetworkController $env:COMPUTERNAME -Credential $Credential -NcRestCredential $NcRestCredential
        $ncClusterSettings = Get-NetworkControllerCluster
        $ncSettings = @{
            NetworkControllerVersion        = (Get-NetworkController).Version
            NetworkControllerClusterVersion = $ncClusterSettings.Version
            ClusterAuthentication = $ncClusterSettings.ClusterAuthentication
        }

        $currentRestCert = Get-SdnNetworkControllerRestCertificate

        if ($ncSettings.ClusterAuthentication -ieq 'X509') {
            $rotateNCNodeCerts = $true
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

        #####################################
        #
        # Create Certificate (Optional)
        #
        #####################################

        if ($GenerateCertificate) {
            "== STAGE: CREATE SELF SIGNED CERTIFICATES ==" | Trace-Output

            $certGenerationInfo = New-SdnNetworkControllerCertificate -NetworkControllers $sdnFabricDetails.NetworkController -ClusterAuthentication $ncSettings.ClusterAuthentication -NcRestName $NcInfraInfo.NcRestName `
                -NotAfter $NotAfter -CertPassword $CertPassword  -Credential $Credential
        }

        #####################################
        #
        # Certificate Seeding
        #
        #####################################

        if ($PSBoundParameters.ContainsKey('GenerateCertificate') -or $PSBoundParameters.ContainsKey('CertPath')) {
            "== STAGE: CERTIFICATE SEEDING ==" | Trace-Output
            Copy-CertificatesToFabric -CertPath $($certGenerationInfo.CertPath).FullName -CertPassword $CertPassword -FabricDetails $sdnFabricDetails -RotateNodeCertificates:$rotateNCNodeCerts
        }

        #####################################
        #
        # Certificate Configuration
        #
        #####################################

        "== STAGE: DETERMINE CERTIFICATE CONFIG ==" | Trace-Output

        $certificateConfig = @{
            RestCert = $null
            NetworkController = @{}
        }

        $updatedRestCertificate = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -ieq $currentRestCert.Subject} `
        | Sort-Object -Property NotBefore -Descending | Select-Object -First 1
        if ($updatedRestCertificate) {
            $certificateConfig.RestCert = $updatedRestCertificate
        }

        if ($rotateNCNodeCerts) {
            foreach ($controller in $sdnFabricDetails.NetworkController) {

                $currentNodeCert = Invoke-PSRemoteCommand -ComputerName $controller -Credential $Credential -ScriptBlock {
                    Get-SdnNetworkControllerNodeCertificate
                }

                $updatedNodeCert = Invoke-PSRemoteCommand -ComputerName $controller -Credential $Credential -ScriptBlock {
                    Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -ieq $using:currentNodeCert.Subject} `
                    | Sort-Object -Property NotBefore -Descending | Select-Object -First 1
                }

                $certificateConfig.NetworkController[$controller] = [PSCustomObject]@{
                    New = $updatedNodeCert
                    Current =  $currentNodeCert
                }
            }
        }

        "Network Controller Rest Certificate {0} will be updated from [Thumbprint:{1} NotAfter:{2}] to [Thumbprint:{3} NotAfter:{4}]" `
        -f $currentRestCert.Subject, $currentRestCert.Thumbprint, $currentRestCert.NotAfter, $certificateConfig.RestCert.Thumbprint, $certificateConfig.RestCert.NotAfter `
        | Trace-Output -Level:Warning

        if ($rotateNCNodeCerts) {
            foreach ($node in $sdnFabricDetails.NetworkController) {
                $nodeCertConfig = $certificateConfig.NetworkController[$node]
                "Network Controller Node Certificate {0} will be updated from [Thumbprint:{1} NotAfter:{2}] to [Thumbprint:{3} NotAfter:{4}]" `
                    -f $nodeCertConfig.Current.Subject, $nodeCertConfig.Current.Thumbprint, $nodeCertConfig.Current.NotAfter, `
                    $nodeCertConfig.New.Thumbprint, $nodeCertConfig.New.NotAfter | Trace-Output -Level:Warning
            }    
        }
        
        $confirm = Confirm-UserInput
        if (-NOT $confirm){
            "User has opted to abort the operation. Terminating operation" | Trace-Output -Level:Warning
            return
        }

        #####################################
        #
        # Rotate NC Northbound Certificate (REST)
        #
        #####################################

        "== STAGE: ROTATE NC REST CERTIFICATE ==" | Trace-Output

        $null = Invoke-CertRotateCommand -Command 'Set-NetworkController' -Credential $Credential -Thumbprint ($certificateConfig.RestCert.Thumbprint).ToString()

        "Waiting for 5 minutes before proceeding to the next step. Script will resume at {0}" -f (Get-Date).AddMinutes(5).ToUniversalTime().ToString() | Trace-Output
        Start-Sleep -Seconds 300

        #####################################
        #
        # Rotate Cluster Certificate
        #
        #####################################

        "== STAGE: ROTATE NC CLUSTER CERTIFICATE ==" | Trace-Output

        $null = Invoke-CertRotateCommand -Command 'Set-NetworkControllerCluster' -Credential $Credential -Thumbprint ($certificateConfig.RestCert.Thumbprint).ToString()

        "Waiting for 5 minutes before proceeding to the next step. Script will resume at {0}" -f (Get-Date).AddMinutes(5).ToUniversalTime().ToString() | Trace-Output
        Start-Sleep -Seconds 300

        #####################################
        #
        # Rotate NC Node Certificates
        #
        #####################################

        if ($rotateNCNodeCerts) {
            "== STAGE: ROTATE NC NODE CERTIFICATE ==" | Trace-Output

            foreach ($node in $sdnFabricDetails.NetworkController){
                $nodeCertConfig = $certificateConfig.NetworkController[$node]
                $null = Invoke-CertRotateCommand -Command 'Set-NetworkControllerNode' -NetworkController $node -Credential $Credential -Thumbprint ($nodeCertConfig.New.Thumbprint).ToString()

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

        $null = Update-NetworkControllerCredentialResource -NcUri $sdnFabricDetails.NcUrl -Credential $NcRestCredential `
        -NewRestCertThumbprint ($certificateConfig.RestCert.Thumbprint).ToString() -ErrorAction Stop

        "Certificate rotation completed successfully" | Trace-Output
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
