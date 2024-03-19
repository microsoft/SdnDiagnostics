function Get-SdnDiscovery {
    <#
    .SYNOPSIS
        Calls to the Discovery API endpoint to determine versioning and feature details
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri.AbsoluteUri -ResourceName 'Discovery'
        $result = Invoke-RestMethodWithRetry -Uri $uri -Method GET -UseBasicParsing -Credential $Credential -ErrorAction Stop
        return $result
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
