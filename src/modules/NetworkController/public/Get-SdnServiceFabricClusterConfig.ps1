# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnServiceFabricClusterConfig {
    <#
    .SYNOPSIS
        Gets Service Fabric Cluster Config Properties.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates. Default to local machine.
    .PARAMETER Uri
        The Uri to read properties from fabric:/NetworkController/ClusterConfiguration, fabric:/NetworkController/GlobalConfiguration
    .PARAMETER Name
        Property Name to filter the result. If not specified, it will return all properties.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnServiceFabricClusterConfig -NetworkController 'NC01' -Uri "fabric:/NetworkController/ClusterConfiguration" -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]$NetworkController = $(HostName),

        [Parameter(Mandatory = $true)]
        [String]$Uri,

        [Parameter(Mandatory = $false)]
        [String]$Name,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty        
    )

    try {
        Connect-ServiceFabricCluster | Out-Null
        $client = [System.Fabric.FabricClient]::new()
        $result = $null
        $binaryMethod = [System.Fabric.NamedProperty].getmethod("GetValue").MakeGenericMethod([byte[]])
        $stringMethod = [System.Fabric.NamedProperty].getmethod("GetValue").MakeGenericMethod([string])
            
        $results = [System.Collections.ArrayList]::new()
        do {
            $result = $client.PropertyManager.EnumeratePropertiesAsync($Uri, $true, $result).Result
            $result.GetEnumerator() | ForEach-Object {
                $propertyName = $_.Metadata.PropertyName
                
                $propertyObj = [PSCustomObject]@{
                    Name = $propertyName
                    Value = $null
                }
                if($_.Metadata.TypeId -ieq "string"){
                    $value = $stringMethod.Invoke($_, $null);
                    $propertyObj.Value = $value

                }elseif($_.Metadata.TypeId -ieq "binary"){
                    # only binary value exist is certificate
                    $value = $binaryMethod.Invoke($_, $null);
                    $certObj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($value)
                    $propertyObj.Value = $certObj
                }

                if($PSBoundParameters.ContainsKey('Name')){
                    if($propertyName -ieq $Name){
                        $results.Add($propertyObj) | Out-Null
                        # Property Name is uniqueue so when name found, return the list
                        return $results
                    }
                }else{
                    $results.Add($propertyObj) | Out-Null
                }
            }
        }
        while ($result.HasMoreData)
        return $results
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
