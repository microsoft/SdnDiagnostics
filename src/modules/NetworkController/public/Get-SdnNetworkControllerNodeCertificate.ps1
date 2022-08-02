# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnNetworkControllerNodeCertificate {
    <#
    .SYNOPSIS

    #>

    try {
        $networkControllerNode = Get-NetworkControllerNode -Name $env:COMPUTERNAME
        "Network Controller is currently configured for FindCertificateBy: {0}" -f $networkControllerNode.FindCertificateBy
        switch ($networkControllerNode.FindCertificateBy) {
            'FindBySubjectName' {
                "`tFindBySubjectName: {0}" -f $networkControllerNode.FindBySubjectName | Trace-Output
                $certificate = Get-SdnCertificate -Path 'Cert:\\LocalMachine\My' -SubjectName $networkControllerNode.NodeCertSubjectName
            }

            'FindByThumbprint' {
                "`FindByThumbprint: {0}" -f $networkControllerNode.FindByThumbprint | Trace-Output
                $certificate = Get-SdnCertificate -Path 'Cert:\\LocalMachine\My' -Thumbprint $networkControllerNode.NodeCertificateThumbprint
            }
        }

        if ($null -eq $certificate) {
            throw New-Object System.NullReferenceException("Unable to locate Network Controller Certificate")
        }

        return $certificate
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
