# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
            $config = Get-SdnRoleConfiguration -Role 'NetworkController'
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
            if (![string]::IsNullOrEmpty($certSubject)) {
                $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName + "." + (get-ciminstance win32_computersystem).Domain
                $certSubject = "CN=$NodeFQDN"
            }
            
            Write-Verbose "Looking for cert match $certSubject"
            $cert = Get-ChildItem -Path Cert:\LocalMachine\My | ? { $_.Subject -ieq $certSubject } | Sort-Object -Property NotBefore -Descending | Select-Object -First 1
            return $cert.Thumbprint
        }
        $CertificateRotationConfig["NcRestCert"] = Invoke-Command -ComputerName $NetworkController -ScriptBlock $getNewestCertScript -ArgumentList "CN=$NcInfraInfo.NcRestName" -Credential $Credential

        if($NcInfraInfo.ClusterCredentialType -eq "X509"){
            foreach ($ncNode in $($NcInfraInfo.NcNodeList)) {
                $ncNodeCert = Invoke-Command -ComputerName $ncNode.IpAddressOrFQDN -ScriptBlock $getNewestCertScript -Credential $Credential
                $CertificateRotationConfig[$ncNode.NodeName.ToLower()] = $ncNodeCert
            }
        }

        return $CertificateRotationConfig
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
