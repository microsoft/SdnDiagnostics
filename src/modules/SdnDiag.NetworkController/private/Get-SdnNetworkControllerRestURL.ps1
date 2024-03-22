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

        # use the Subject of the ServerCertificate object back for the NB API
        $endpoint = $result.ServerCertificate.Subject.Split('=')[1]
        $ncUrl = 'https://{0}' -f $endpoint

        return $ncUrl
    }
    catch {
        $_ | Trace-Exception
    }
}
