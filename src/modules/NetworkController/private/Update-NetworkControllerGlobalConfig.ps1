# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Update-NetworkControllerGlobalConfig {
    <#
    .SYNOPSIS
        Update the Network Controller Application Global Config with new certificate info.
    .PARAMETER NcNodeList
        The NcNodeList that retrieved via Get-SdnNetworkControllerInfoOffline.
    .PARAMETER NcRestName
        The Network Controller REST name in FQDN format.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $NcNodeList,
        [Parameter(Mandatory = $true)]
        [String]
        $NcRestName,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $NcVMs = $NcNodeList.IpAddressOrFQDN
        if ($NcVMs.Count -eq 0) {
            Trace-Output "No NC VMs found" -Level:Error
            return
        }

        $ncNodeCertInfo = @{}

        $ncRestCert = Get-NetworkControllerCertificate -NetworkController $NcVMs[0] -NcRestName $NcRestName -Credential $Credential
        $ncNodeCertInfo["RestCert"] = $ncRestCert

        foreach ($ncNode in $NcNodeList) {
            $ncNodeCert = Get-NetworkControllerCertificate -NetworkController $ncNode.IpAddressOrFQDN -Credential $Credential
            $ncNodeCertInfo[$ncNode.NodeName.ToLower()] = $ncNodeCert
        }

        $updateNcConfigScript = {
            param(
                [PSCustomObject]
                $NcNodeCertInfo
            )
            function PutProperty {
                param(
                    $Uri = "fabric:/NetworkController/GlobalConfiguration",
                    [Parameter(Mandatory)]
                    $Property,
                    [Parameter(Mandatory)]
                    $Value
                )

                try {
                    $task = $null
                    $client = $null
                    Connect-ServiceFabricCluster | Out-Null
                    $client = [System.Fabric.FabricClient]::new()
                    $task = $client.PropertyManager.PutPropertyAsync($Uri, $Property, $value)
                    $task.Wait()
                }
                catch {
                    throw
                }
                finally {
                    if ($null -ne $client) {
                        $client.Dispose()
                    }
                }
            }

            Write-Host "Updating NetworkController Global Config with certs"
            $NcNodeCertInfo

            Write-Host "Current NetworkController Global Config:"
            $newConfigs = [System.Collections.ArrayList]::new()

            Connect-ServiceFabricCluster | Out-Null
            $client = [System.Fabric.FabricClient]::new()
            $result = $null
            $method = [System.Fabric.NamedProperty].getmethod("GetValue").MakeGenericMethod([string])
            do {
                $result = $client.PropertyManager.EnumeratePropertiesAsync("fabric:/NetworkController/GlobalConfiguration", $true, $result).Result
                $result.GetEnumerator() | ForEach-Object {
                    $name = $_.Metadata.PropertyName
                    $value = $method.Invoke($_, $null);
                    if ($name.StartsWith("Global") -and ($name.Contains("Thumbprint") -or $name.Contains("SSL"))) {
                        "Name: " + $name + " , " + "Value: " + $value

                        $newConfig = $null
                        if ($name.Contains("SSL")) {
                            # $newConfig = [PSCustomObject]@{
                            #     Name  = $name
                            #     Value = $using:ncNodeCertInfo['RestCert']
                            # }
                        }
                        elseif ($name.Contains("Thumbprint")) {
                            foreach ($certInfoKey in $NcNodeCertInfo.Keys) {
                                Write-Verbose "Looking for node match $name"
                                if ($name -match $certInfoKey) {
                                    $newConfig = [PSCustomObject]@{
                                        Name  = $name
                                        Value = $($NcNodeCertInfo).$certInfoKey
                                    }
                                    Write-Verbose "Found thumbprint: $($newConfig.Value)"
                                }
                            }
                        }

                        if ($null -ne $newConfig) {
                            $newConfigs.Add($newConfig) | Out-Null
                        }
                    }
                }
            }
            while ($result.HasMoreData)

            Write-Host "Updating with new NetworkController Global Config:"
        
            foreach ($newConfig in $newConfigs) {
                Write-Host "name: $($newConfig.Name) value: $($newConfig.Value)"
                PutProperty -Property $($newConfig.Name) -Value $($newconfig.Value)
            }
        }

        $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName + "." + (get-ciminstance win32_computersystem).Domain
        if($NcVMs -contains $NodeFQDN){
            Invoke-Command -ScriptBlock $updateNcConfigScript -ArgumentList $ncNodeCertInfo
        }
        else{   
            Invoke-Command -ComputerName $($NcVms[0]) -ScriptBlock $updateNcConfigScript -ArgumentList $ncNodeCertInfo -Credential $Credential
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}