function Set-SdnNetworkController {
    <#
    .SYNOPSIS
        Sets network controller application settings.
    .PARAMETER RestIPAddress
        Specifies the IP address on which network controller nodes communicate with the REST clients. This IP address must not be an existing IP address on any of the network controller nodes.
    .PARAMETER RestName
        Switch parameter to configure the network controller application to use the server certificate's subject name as the REST endpoint name.
    .PARAMETER Credential
        Specifies a user credential that has permission to perform this action. The default is the current user.
        Specify this parameter only if you run this cmdlet on a computer that is not part of the network controller cluster.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'RestIPAddress')]
        [ValidateScript({
            $split = $_.split('/')
            if ($split.count -ne 2) { throw "RestIpAddress must be in CIDR format."}
            if (!($split[0] -as [ipaddress] -as [bool])) { throw "Invalid IP address specified in RestIpAddress."}
            if (($split[1] -le 0) -or ($split[1] -gt 32)) { throw "Invalid subnet bits specified in RestIpAddress."}
            return $true
        })]
        [System.String]$RestIpAddress,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestName')]
        [Switch]$RestName,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestIPAddress')]
        [Parameter(Mandatory = $false, ParameterSetName = 'RestName')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential
    )

    $waitDuration = 30 # seconds
    $params = @{}
    if ($Credential -ne [System.Management.Automation.PSCredential]::Empty -and $null -ne $Credential) {
        $params.Add('Credential', $Credential)
    }

    Confirm-IsAdmin
    Confirm-IsNetworkController
    if ($PSSenderInfo) {
        if ($Credential -eq [System.Management.Automation.PSCredential]::Empty -or $null -eq $Credential) {
            throw New-Object System.NotSupportedException("This operation is not supported in a remote session without supplying -Credential.")
        }
    }

    try {
        $getNetworkController = Get-SdnNetworkController
        if ($null -eq $getNetworkController) {
            throw New-Object System.Exception("Unable to retrieve results from Get-SdnNetworkController.")
        }

        $certSubjectName = $getNetworkController.ServerCertificate.Subject.Split('=')[1].Trim()
        if ($null -eq $certSubjectName) {
            throw New-Object System.Exception("Unable to retrieve current ServerCertificate.Subject property")
        }

        Connect-ServiceFabricCluster | Out-Null
        $param = Get-ServiceFabricApplication -ApplicationName 'fabric:/NetworkController' -ErrorAction Stop
        $version = $param.ApplicationParameters["SDNAPIConfigVersion"].Value
        $client=[System.Fabric.FabricClient]::new()

        switch ($PSCmdlet.ParameterSetName) {
            'RestName' {
                $params.Add('RestName', $certSubjectName)

                if ($getNetworkController.RestName) {
                    "Network Controller is already configured with RestName: {0}" -f $getNetworkController.RestName | Trace-Output -Level:Warning
                    return
                }

                else {
                    # if we changing from RestIPAddress to RestName, then we need to remove the RestIPAddress property and add the RestURL property
                    # once we remove the RestIPAddress property, we can perform a PUT operation to set the RestURL property
                    "Operation will set RestName to {0}." -f $certSubjectName | Trace-Output -Level:Warning
                    $confirm = Confirm-UserInput -Message "Do you want to proceed with operation? [Y/N]:"
                    if ($confirm) {
                        "Deleting the current RestIPAddress property" | Trace-Output
                        $client.PropertyManager.DeletePropertyAsync("fabric:/NetworkController/GlobalConfiguration", "SDNAPI.$version.RestIPAddress")
                        $client.PropertyManager.PutPropertyAsync("fabric:/NetworkController/GlobalConfiguration", "SDNAPI.$version.RestURL", $certSubjectName)
                    }
                    else {
                        "User has opted to abort the operation. Terminating operation" | Trace-Output
                        return
                    }
                }
            }

            'RestIPAddress' {
                $params.Add('RestIPAddress', $RestIpAddress)

                # check to see if the RestIPAddress is already configured, if so, then cross-compare the value currently configured with the new value
                # if we are just changing from one IP to another, then we can just update the value using Set-NetworkController
                if ($getNetworkController.RestIPAddress) {
                    if ($getNetworkController.RestIPAddress -ieq $RestIpAddress) {
                        "RestIPAddress is already set to {0}. Aborting operation." -f $getNetworkController.RestIPAddress | Trace-Output -Level:Warning
                        return
                    }
                    else {
                        "RestIPAddress is currently set to {0}. Operation will set RestIPAddress to {1}." -f $getNetworkController.RestIPAddress, $RestIpAddress | Trace-Output -Level:Warning
                        $confirm = Confirm-UserInput -Message "Do you want to proceed with operation? [Y/N]:"
                        if ($confirm) {
                            # do nothing here directly, since we will be calling Set-NetworkController later on
                        }
                        else {
                            "User has opted to abort the operation. Terminating operation" | Trace-Output
                            return
                        }
                    }
                }

                # if we changing from RestName to RestIPAddress, then we need to remove the RestURL property and add the RestIPAddress property
                # once we remove the RestUrl property, we need to insert a dummy CIDR value to ensure that the Set-NetworkController operation does not fail
                else {
                    "Operation will set RestIPAddress to {0}." -f $RestIpAddress | Trace-Output -Level:Warning
                    $confirm = Confirm-UserInput -Message "Do you want to proceed with operation? [Y/N]:"
                    if ($confirm) {
                        "Deleting the current RestURL property and inserting temporary RestIPAddress" | Trace-Output
                        $client.PropertyManager.DeletePropertyAsync("fabric:/NetworkController/GlobalConfiguration", "SDNAPI.$version.RestURL")
                        $client.PropertyManager.PutPropertyAsync("fabric:/NetworkController/GlobalConfiguration", "SDNAPI.$version.RestIPAddress", "10.65.15.117/27")
                    }
                    else {
                        "User has opted to abort the operation. Terminating operation" | Trace-Output
                        return
                    }
                }
            }
        }

        "Sleeping for {0} seconds" -f $waitDuration | Trace-Output
        Start-Sleep -Seconds $waitDuration # wait for the property to be deleted

        "Calling Set-NetworkController with params: {0}" -f ($params | ConvertTo-Json) | Trace-Output
        Set-NetworkController @params

        return (Get-SdnNetworkController)
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
    finally {
        if ($client) {
            $client.Dispose()
        }
    }
}
