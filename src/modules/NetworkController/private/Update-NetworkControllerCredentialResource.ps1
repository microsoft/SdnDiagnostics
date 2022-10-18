# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Update-NetworkControllerCredentialResource {
    <#
    .SYNOPSIS
        Update the Credential Resource in Network Controller with new certificate.
    .PARAMETER NcUri
        The Network Controller REST URI.
    .PARAMETER NewRestCertThumbprint
        The new Network Controller REST Certificate Thumbprint to be used by credential resource.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]
        $NcUri,
        [Parameter(Mandatory = $true)]
        [String]
        $NewRestCertThumbprint,
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty   
    )

    try {
        $uri = "$NcUri/networking/v1/servers"

        $servers = Get-SdnServer -NcUri $NcUri -Credential $Credential
        if ($null -ne $server) {
            $certConn = $servers[0].properties.connections | Where-Object { $_.credentialType -match "X509Certificate" }
            if ($null -ne $certConn) {
                $certCredResource = Get-SdnResource -NcUri $NcUri -Credential $Credential -ResourceRef $con.credential.resourceRef
                if ($null -eq $certCredResource) {
                    $certCredResource.value = $NewRestCertThumbprint
                    $body = $certCredResource | ConvertTo-Json -Depth 10
            
                    Invoke-WebRequestWithRetry -Method 'Put' -Uri $uri -Credential $Credential -Body $body -UseBasicParsing `
                    -Content "application/json; charset=UTF-8" -Headers @{"Accept" = "application/json"}
                }
            }else{
                Trace-Output "No Credential Resources of type X509Certificate Found."
            }
        }else{
            Trace-Output "No Server Resources Found."
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}