function Get-SdnNetworkControllerRestURL {
    <#
        .SYNOPSIS
        Queries Network Controller to identify the Rest URL endpoint that can be used to query the north bound API endpoint.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]$NetworkController = $env:COMPUTERNAME,

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

        switch ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType) {
            'FailoverCluster' {
                $result = Get-SdnNetworkControllerFC @PSBoundParameters -ErrorAction Stop
                $endpoint = $result.RestCertificateSubjectName
            }
            'ServiceFabric' {
                $result = Get-SdnNetworkControllerSF @PSBoundParameters -ErrorAction Stop
                $endpoint = $result.ServerCertificate.Subject.Split('=')[1]
            }
        }

        $ncUrl = 'https://{0}' -f $endpoint
        return $ncUrl
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
