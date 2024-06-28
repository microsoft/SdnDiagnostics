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

    # if already populated into the cache, return the value
    if (-NOT ([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.EnvironmentInfo.NcUrl))) {
        return $Global:SdnDiagnostics.EnvironmentInfo.NcUrl
    }

    try {
        switch ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType) {
            'FailoverCluster' {
                $result = Get-SdnNetworkControllerFC @PSBoundParameters -ErrorAction Stop
                if ($result) {
                    $endpoint = $result.RestCertificateSubjectName
                }
            }
            'ServiceFabric' {
                $result = Get-SdnNetworkControllerSF @PSBoundParameters -ErrorAction Stop
                if ($result) {
                    $endpoint = $result.ServerCertificate.Subject.Split('=')[1]
                }
            }
        }
    }
    catch {
        $_ | Trace-Exception
        throw $_
    }

    if (-NOT [string]::IsNullOrEmpty($endpoint)) {
        $ncUrl = 'https://{0}' -f $endpoint
        return $ncUrl
    }
    else {
        throw New-Object System.NullReferenceException("Failed to retrieve Network Controller Rest URL.")
    }
}
