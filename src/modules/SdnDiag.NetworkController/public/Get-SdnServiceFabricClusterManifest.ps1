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

    if (-NOT ($PSBoundParameters.ContainsKey('NetworkController'))) {
        $config = Get-SdnModuleConfiguration -Role 'NetworkController'
        $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
        if (-NOT ($confirmFeatures)) {
            "The current machine is not a NetworkController, run this on NetworkController or use -NetworkController parameter to specify one" | Trace-Output -Level:Warning
            return # don't throw exception, since this is a controlled scenario and we do not need stack exception tracing
        }
    }

    try {

        # in instances where Service Fabric is down/offline we want to catch any exceptions returned by Invoke-SdnServiceFabricCommand
        # and then fallback to getting the cluster manifest information from the file system directly
        try {
            $clusterManifest = Invoke-SdnServiceFabricCommand -NetworkController $NetworkController -ScriptBlock { Get-ServiceFabricClusterManifest } -Credential $Credential -ErrorAction Stop
        }
        catch {
            "Unable to retrieve ClusterManifest directly from Service Fabric. Attempting to retrieve ClusterManifest from file system" | Trace-Output -Level:Warning

            $clusterManifestScript = {
                $clusterManifestFile = Get-ChildItem -Path "$env:ProgramData\Microsoft\Service Fabric" -Recurse -Depth 2 -Filter "ClusterManifest.current.xml" -ErrorAction SilentlyContinue
                if ($clusterManifestFile) {
                    $clusterManifest = Get-Content -Path $clusterManifestFile.FullName -ErrorAction Ignore
                    return $clusterManifest
                }

                return $null
            }

            if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
                $clusterManifest = Invoke-Command -ScriptBlock $clusterManifestScript
            }
            else {
                $clusterManifest = Invoke-PSRemoteCommand -ComputerName $NetworkController -Credential $Credential -ScriptBlock $clusterManifestScript
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

        return $xmlClusterManifest
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
