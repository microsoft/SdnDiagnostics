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

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $NcUri,

        [Parameter(Mandatory = $true)]
        [System.String]
        $NewRestCertThumbprint,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate
    )
    $putParams = @{
        Uri             = $null
        Method          = 'Put'
        Headers         = @{"Accept" = "application/json" }
        Content         = "application/json; charset=UTF-8"
        Body            = "{}"
        UseBasicParsing = $true
    }
    $confirmStateParams = @{
        TimeoutInSec = 600
        UseBasicParsing = $true
    }
    $ncRestParams = @{
        NcUri = $NcUri
    }

    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $confirmStateParams.Add('NcRestCertificate', $NcRestCertificate)
            $putParams.Add('Certificate', $NcRestCertificate)
            $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $confirmStateParams.Add('NcRestCredential', $NcRestCredential)
            $putParams.Add('Credential', $NcRestCredential)
            $ncRestParams.Add('NcRestCredential', $NcRestCredential)
        }
    }

    $servers = Get-SdnServer @ncRestParams
    foreach ($object in $servers) {
        "Processing X509 connections for {0}" -f $object.resourceRef | Trace-Output
        foreach ($connection in $servers.properties.connections | Where-Object { $_.credentialType -ieq "X509Certificate" -or $_.credentialType -ieq "X509CertificateSubjectName" }) {
            $cred = Get-SdnResource @ncRestParams -ResourceRef $connection.credential.resourceRef

            # if for any reason the certificate thumbprint has been updated, then skip the update operation for this credential resource
            if ($cred.properties.value -ieq $NewRestCertThumbprint) {
                "{0} has already updated to {1}" -f $cred.resourceRef, $NewRestCertThumbprint | Trace-Output
                continue
            }

            "{0} will be updated from {1} to {2}" -f $cred.resourceRef, $cred.properties.value, $NewRestCertThumbprint | Trace-Output
            $cred.properties.value = $NewRestCertThumbprint
            $putParams.Body = $cred | ConvertTo-Json -Depth 100
            $putParams.Uri = Get-SdnApiEndpoint -NcUri $NcUri -ResourceRef $cred.resourceRef

            # update the credential resource with new certificate thumbprint
            # and confirm the provisioning state is succeeded
            $null = Invoke-WebRequestWithRetry @putParams
            try {
                Confirm-ProvisioningStateSucceeded -NcUri $putParams.Uri @confirmStateParams
            }
            catch {
                $_ | Trace-Exception
                $_ | Write-Error
            }
        }
    }
}
