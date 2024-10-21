function Get-SdnDiscovery {
    <#
    .SYNOPSIS
        Calls to the Discovery API endpoint to determine versioning and feature details
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER Certificate
        Specifies the client certificate that is used for a secure web request. Enter a variable that contains a certificate or a command or expression that gets the certificate.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false, ParameterSetName = 'Credential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [X509Certificate]$Certificate
    )

    $params = @{
        NcUri = $NcUri
        Resource = 'Discovery'
    }
    if ($Certificate) {
        $params.Add('Certificate', $Certificate)
    }
    else {
        $params.Add('Credential', $Credential)
    }

    try {
        $result = Get-SdnResource @params
        return $result
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
