# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-NetworkControllerCertificate {
    <#
    .SYNOPSIS
        Get the Certificate Thumbprint from Network Controller. If $NcRestName specified return Network Controller REST Certificate, otherwise return the node certificate.
        The command return the latest issued (sort by NotBefore of the certificate and return the first one) certificate.
    .PARAMETER NetworkController
        Specifie the Network Controller VM to return certificate.
    .PARAMETER NcRestName
        If Network Controller REST Certificate needed, specify the NcRestName.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $NetworkController,
        [Parameter(Mandatory = $false)]
        [String]
        $NcRestName = $null,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        return Invoke-Command -ComputerName $NetworkController -ScriptBlock {
            $certSubject = ""
            if (![string]::IsNullOrEmpty($using:NcRestName)) {
                $certSubject = "CN=$using:NcRestName"
            }
            else {
                $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName + "." + (get-ciminstance win32_computersystem).Domain
                $certSubject = "CN=$NodeFQDN"
            }
            
            Write-Verbose "Looking for cert match $certSubject"
            $cert = Get-ChildItem -Path Cert:\LocalMachine\My | ? { $_.Subject -ieq $certSubject } | Sort-Object -Property NotBefore -Descending | Select-Object -First 1
            # $cert | ft Subject, Thumbprint, NotBefore, NotAfter 
            return $cert.Thumbprint
        } -Credential $Credential
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}