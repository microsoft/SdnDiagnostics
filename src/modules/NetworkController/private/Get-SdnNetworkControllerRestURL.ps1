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

        $result = Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock { Get-NetworkController } -Credential $Credential

        # check to see if RestName is populated and return back to the caller
        if ($result.RestName) {
            if ($result.ServerCertificate) {
                return ("https://$($result.RestName)")
            }

            return ("http://$($result.RestName)")
        }

        return $null
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
