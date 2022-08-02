# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnNetworkControllerRestCertificate {
    <#
    .SYNOPSIS

    #>

    try {
        $networkController = Get-NetworkController
        $certificate = Get-SdnCertificate -Path 'Cert:\\LocalMachine\My' -SubjectName $networkController.ServerCertificate.Thumbprint

        if ($null -eq $certificate) {
            throw New-Object System.NullReferenceException("Unable to locate Network Controller Rest Certificate")
        }

        return $certificate
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
