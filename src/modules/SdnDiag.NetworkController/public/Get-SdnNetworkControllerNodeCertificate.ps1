function Get-SdnNetworkControllerNodeCertificate {
    <#
    .SYNOPSIS
        Returns the current Network Controller node certificate
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    if ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType -ine 'ServiceFabric') {
        throw New-Object System.NotSupportedException("This function is only supported on Service Fabric clusters.")
    }

    Confirm-IsNetworkController

    try {
        $networkControllerNode = Get-SdnNetworkControllerSFNode -Name $env:ComputerName -Credential $Credential

        # check to see if FindCertificateBy property exists as this was added in later builds
        # else if does not exist, default to Thumbprint for certificate
        if ($null -ne $networkControllerNode.FindCertificateBy) {
            "Network Controller is currently configured for FindCertificateBy: {0}" -f $networkControllerNode.FindCertificateBy | Trace-Output -Level:Verbose
            switch ($networkControllerNode.FindCertificateBy) {
                'FindBySubjectName' {
                    "`tFindBySubjectName: {0}" -f $networkControllerNode.NodeCertSubjectName | Trace-Output -Level:Verbose
                    $certificate = Get-SdnCertificate -Path 'Cert:\LocalMachine\My' -Subject "CN=$($networkControllerNode.NodeCertSubjectName)"
                }

                'FindByThumbprint' {
                    "`FindByThumbprint: {0}" -f $networkControllerNode.NodeCertificateThumbprint | Trace-Output -Level:Verbose
                    $certificate = Get-SdnCertificate -Path 'Cert:\LocalMachine\My' -Thumbprint $networkControllerNode.NodeCertificateThumbprint
                }
            }
        }
        else {
            $certificate = Get-SdnCertificate -Path 'Cert:\LocalMachine\My' -Thumbprint $networkControllerNode.NodeCertificateThumbprint
        }

        if ($null -eq $certificate) {
            throw New-Object System.NullReferenceException("Unable to locate Network Controller Certificate")
        }

        return $certificate
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
