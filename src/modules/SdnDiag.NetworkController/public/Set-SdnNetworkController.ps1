function Set-SdnNetworkController {
    <#
    .SYNOPSIS
        Sets network controller application settings.
    .PARAMETER RestIPAddress
        Specifies the IP address on which network controller nodes communicate with the REST clients. This IP address must not be an existing IP address on any of the network controller nodes.
    .PARAMETER RestName
        Specifies the DNS name of the Network Controller cluster. This must be specified if the Network Controller nodes are in different subnets. In this case, you must also enable dynamic registration of the RestName on the DNS servers.
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
        [System.String]$RestName,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestIPAddress')]
        [Parameter(Mandatory = $false, ParameterSetName = 'RestName')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential
    )

    # ensure that the module is running as local administrator
    $elevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-NOT $elevated) {
        throw New-Object System.Exception("This function requires elevated permissions. Run PowerShell as an Administrator and import the module again.")
    }

    # add disclaimer that this feature is currently under preview
    "This feature is currently under preview. Please report any issues to https://github.com/microsoft/SdnDiagnostics/issues so we can accurately track any issues." | Trace-Output -Level:Warning
    $confirm = Confirm-UserInput -Message "Do you want to proceed with operation? [Y/N]:"
    if (-NOT $confirm) {
        "User has opted to abort the operation. Terminating operation" | Trace-Output -Level:Warning
        return
    }

    try {
        $getNetworkController = Get-SdnNetworkController
        if ($null -eq $getNetworkController) {
            throw New-Object System.Exception("Unable to retrieve network controller information.")
        }

        Connect-ServiceFabricCluster | Out-Null
        $param = Get-ServiceFabricApplication -ApplicationName 'fabric:/NetworkController' -ErrorAction Stop
        $version = $param.ApplicationParameters["SDNAPIConfigVersion"].Value
        $client=[System.Fabric.FabricClient]::new()

        switch ($PSBoundParameters.ParameterSetName) {
            'RestName' {
                if ($getNetworkController.RestName) {
                    $currentRestName = $getNetworkController.ServerCertificate.Thumbprint.Split('=')[1].Trim()
                    if ($currentRestName -ieq $RestName) {
                        "RestName is already set to {0}. Aborting operation." -f $currentRestName | Trace-Output -Level:Warning
                        return
                    }
                    else {
                        "Set-SdnNetworkController does not support changing RestName. Please use Set-NetworkController instead to update the RestName." | Trace-Output -Level:Warning
                        return
                    }
                }

                # if we changing from RestIPAddress to RestName, then we need to remove the RestIPAddress property and add the RestName property
                else {
                    "RestName is not configured. Configuring RestName to {0}. Operation will take several minutes." -f $RestName | Trace-Output -Level:Warning
                    $confirm = Confirm-UserInput -Message "Do you want to proceed with operation? [Y/N]:"
                    if ($confirm) {
                        $client.PropertyManager.DeletePropertyAsync("fabric:/NetworkController/GlobalConfiguration", "SDNAPI.$version.RestIPAddress")

                        Start-Sleep -Seconds 30 # wait for the property to be deleted
                        Set-NetworkController @PSBoundParameters
                    }
                    else {
                        "User has opted to abort the operation. Terminating operation" | Trace-Output
                        return
                    }
                }
            }

            'RestIPAddress' {
                # check to see if the RestIPAddress is already configured, if so, then cross-compare the value currently configured with the new value
                # if we are just changing from one IP to another, then we can just update the value using Set-NetworkController
                if ($getNetworkController.RestIPAddress) {
                    if ($getNetworkController.RestIPAddress -ieq $RestIpAddress) {
                        "RestIPAddress is already set to {0}. Aborting operation." -f $getNetworkController.RestIPAddress | Trace-Output -Level:Warning
                        return
                    }
                    else {
                        "RestIPAddress is currently set to {0}. Changing to {1}." -f $getNetworkController.RestIPAddress, $RestIpAddress | Trace-Output -Level:Warning
                        $confirm = Confirm-UserInput -Message "Do you want to proceed with operation? [Y/N]:"
                        if ($confirm) {
                            "Configuring RestIPAddress to {0}. Operation will take several minutes." -f $RestIpAddress | Trace-Output -Level:Verbose
                            Set-NetworkController @PSBoundParameters
                        }
                        else {
                            "User has opted to abort the operation. Terminating operation" | Trace-Output
                            return
                        }
                    }
                }

                # if we changing from RestName to RestIPAddress, then we need to remove the RestName property and add the RestIPAddress property
                # once we remove the RestUrl property, we need to insert a dummy CIDR value to ensure that the Set-NetworkController operation does not fail
                else {
                    "RestIPAddress is not configured. Configuring RestIPAddress to {0}. Operation will take several minutes." -f $RestIpAddress | Trace-Output -Level:Warning
                    $confirm = Confirm-UserInput -Message "Do you want to proceed with operation? [Y/N]:"
                    if ($confirm) {
                        $client.PropertyManager.DeletePropertyAsync("fabric:/NetworkController/GlobalConfiguration", "SDNAPI.$version.RestURL")
                        $client.PropertyManager.PutPropertyAsync("fabric:/NetworkController/GlobalConfiguration", "SDNAPI.$version.RestIPAddress", "10.65.15.117/27")

                        Start-Sleep -Seconds 30 # wait for the property to be deleted
                        Set-NetworkController @PSBoundParameters
                    }
                    else {
                        "User has opted to abort the operation. Terminating operation" | Trace-Output
                        return
                    }
                }
            }
        }

        return (Get-SdnNetworkController)
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
