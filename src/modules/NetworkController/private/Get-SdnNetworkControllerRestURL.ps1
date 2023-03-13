# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnNetworkControllerRestURL {
    <#
        .SYNOPSIS
            Queries Network Controller to identify the Rest URL endpoint that can be used to query the north bound API endpoint.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$NetworkController,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        # if already populated into the cache, return the value
        if (-NOT ([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.EnvironmentInfo.NcUrl))) {
            return $Global:SdnDiagnostics.EnvironmentInfo.NcUrl
        }

        $result = Get-SdnNetworkController -NetworkController $NetworkController -Credential $Credential
        if ($null -eq $result) {
            throw New-Object System.NullReferenceException("Unable to return information from Network Controller")
        }

        # determine if we are using X509 authentication
        if ($result.ServerCertificate) {
            $protocol = 'https'
        }
        else {
            $protocol = 'http'
        }

        # determine if we are using FQDN or IP Address for our NC URL
        if ($result.RestName) {
            $url = $result.RestName
        }
        elseif ($result.RestIPAddress) {
            $url = $result.RestIPAddress
        }
        else {
            throw New-Object System.NullReferenceException("Unable to determine REST URL")
        }

        # generate the url based on the values identified previously
        $ncUrl = "{0}/{1}" -f $protocol, $url
        return $ncUrl
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
