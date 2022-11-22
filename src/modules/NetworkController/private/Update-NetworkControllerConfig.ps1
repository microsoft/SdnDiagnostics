# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
            Set-SdnServiceFabricClusterConfig -Uri $globalConfigUri -Name $thumbprintProperty.Name -Value $nodeCertThumbprint
        }

        # Cluster Config property name like NodeName.ClusterCertThumbprint
        $thumbprintProperty = $clusterConfigs | Where-Object Name -ieq $thumbprintPropertyName
        
        # If NodeName.ClusterCertThumbprint exist (for Server 2022 +), Update
        if($null -ne $thumbprintProperty){
            "ClusterConfiguration: Property $($thumbprintProperty.Name) will be updated from $($thumbprintProperty.Value) to $nodeCertThumbprint" | Trace-Output
            Set-SdnServiceFabricClusterConfig -Uri $clusterConfigUri -Name $thumbprintProperty.Name -Value $nodeCertThumbprint
        }

        $certProperty = $clusterConfigs | Where-Object Name -ieq $ncNode.NodeName
        if($null -ne $certProperty){
            $nodeCert = Invoke-Command $ncNode.IpAddressOrFQDN -ScriptBlock{
                return Get-Item Cert:\LocalMachine\My\$using:nodeCertThumbprint
            }
            "ClusterConfiguration: Property $($certProperty.Name) will be updated From :`n$($certProperty.Value) `nTo : `n$nodeCert" | Trace-Output
            Set-SdnServiceFabricClusterConfig -Uri $clusterConfigUri -Name $certProperty.Name -Value $nodeCert.GetRawCertData()
        }
    }
}