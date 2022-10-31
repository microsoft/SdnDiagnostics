# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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

        $clusterManifestXml = [xml](Get-SdnServiceFabricClusterManifest -NetworkController $NetworkController -Credential $Credential)
        $NodeList = $clusterManifestXml.ClusterManifest.Infrastructure.WindowsServer.NodeList.Node
        $securitySection = $clusterManifestXml.ClusterManifest.FabricSettings.Section | Where-Object Name -eq "Security"
        $ClusterCredentialType = $securitySection.Parameter | Where-Object Name -eq "ClusterCredentialType"
        $secretCertThumbprint = $clusterManifestXml.ClusterManifest.Certificates.SecretsCertificate.X509FindValue

        $ncRestName = Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock{
            $secretCert = Get-Item "Cert:LocalMachine\My\$using:secretCertThumbprint"
            if($null -eq $secretCert)
            {
                Write-Host "[$(HostName)] NetworkController secret certificate with thumbprint $secretCertThumbprint not found" -ForegroundColor:Yellow
                return $null
            }
            else
            {
                return $secretCert.Subject.Replace("CN=","")
            }
        } -Credential $Credential

        $infraInfo = [PSCustomObject]@{
            ClusterCredentialType = $ClusterCredentialType.Value
            NodeList = $NodeList
            NcRestName = $ncRestName
        }

        return $infraInfo

    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
