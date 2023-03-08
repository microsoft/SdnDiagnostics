function Get-SdnNetworkControllerRestCertificate {
    <#
    .SYNOPSIS
        Returns the current Network Controller REST Certificate
    #>

    try {

        $config = Get-SdnRoleConfiguration -Role 'NetworkController'
        $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
        if (-NOT ($confirmFeatures)) {
            "The current machine is not a NetworkController, run this on NetworkController or use -NetworkController parameter to specify one" | Trace-Output -Level:Warning
            return # don't throw exception, since this is a controlled scenario and we do not need stack exception tracing
        }

        try {
            $networkController = Get-SdnNetworkController
            $ncRestCertThumprint = $($networkController.ServerCertificate.Thumbprint).ToString()
        }
        catch {
            "Unable to retrieve NetworkController Certificate Info directly from Get-NetworkController. Attempting to retrieve info from ClusterManifest" | Trace-Output -Level:Warning
            $ncInfo = Get-SdnNetworkControllerInfoOffline
            $ncRestCertThumprint = $ncInfo.NcRestCertThumbprint
        }

        $certificate = Get-SdnCertificate -Path 'Cert:\LocalMachine\My' -Thumbprint $ncRestCertThumprint

        if ($null -eq $certificate) {
            throw New-Object System.NullReferenceException("Unable to locate Network Controller Rest Certificate")
        }

        return $certificate
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
