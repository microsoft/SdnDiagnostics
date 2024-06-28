function Get-SdnServiceFabricClusterConfig {
    <#
    .SYNOPSIS
        Gets Service Fabric Cluster Config Properties.
    .PARAMETER Uri
        The Uri to read properties from ClusterConfiguration, GlobalConfiguration
    .PARAMETER Name
        Property Name to filter the result. If not specified, it will return all properties.
    .EXAMPLE
        PS> Get-SdnServiceFabricClusterConfig -Uri "ClusterConfiguration"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('GlobalConfiguration', 'ClusterConfiguration')]
        [String]$Uri,

        [Parameter(Mandatory = $false)]
        [String]$Name
    )

    Confirm-IsNetworkController
    $results = [System.Collections.ArrayList]::new()

    try {
        Connect-ServiceFabricCluster | Out-Null

        $client = [System.Fabric.FabricClient]::new()
        $result = $null
        $absoluteUri = "fabric:/NetworkController/$Uri"
        $binaryMethod = [System.Fabric.NamedProperty].getmethod("GetValue").MakeGenericMethod([byte[]])
        $stringMethod = [System.Fabric.NamedProperty].getmethod("GetValue").MakeGenericMethod([string])

        do {
            $result = $client.PropertyManager.EnumeratePropertiesAsync($absoluteUri, $true, $result).Result
            $result.GetEnumerator() | ForEach-Object {
                $propertyObj = [PSCustomObject]@{
                    Name  = $_.Metadata.PropertyName
                    Value = $null
                }

                if ($_.Metadata.TypeId -ieq "string") {
                    $value = $stringMethod.Invoke($_, $null);
                    $propertyObj.Value = $value

                }
                elseif ($_.Metadata.TypeId -ieq "binary") {
                    # only binary value exist is certificate
                    $value = $binaryMethod.Invoke($_, $null);
                    $certObj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($value)
                    $propertyObj.Value = $certObj
                }

                if ($PSBoundParameters.ContainsKey('Name')) {
                    # PropertyName is unique so when name found, return the list
                    if ($_.Metadata.PropertyName -ieq $Name) {
                        [void]$results.Add($propertyObj)
                        return $results
                    }
                }
                else {
                    [void]$results.Add($propertyObj)
                }
            }
        }
        while ($result.HasMoreData)

        return $results
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
