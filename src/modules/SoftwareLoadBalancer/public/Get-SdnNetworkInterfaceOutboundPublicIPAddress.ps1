function Get-SdnNetworkInterfaceOutboundPublicIPAddress {
    <#
    .SYNOPSIS
        Gets the outbound public IP address that is used by a network interface
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [uri]$NcUri,

        [Parameter(Mandatory = $true)]
        [System.String]$ResourceId,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )
    try {
        $arrayList = [System.Collections.ArrayList]::new()

        $networkInterface = Get-SdnResource -NcUri $NcUri.AbsoluteUri -ResourceType:NetworkInterfaces -Credential $Credential | Where-Object { $_.resourceId -ieq $ResourceId }
        if ($null -eq $networkInterface) {
            throw New-Object System.NullReferenceException("Unable to locate network interface within Network Controller")
        }

        foreach ($ipConfig in $networkInterface.properties.ipConfigurations) { 
            $publicIpRef = Get-PublicIpReference -NcUri $NcUri.AbsoluteUri -IpConfiguration $ipConfig -Credential $Credential
            if ($publicIpRef) {
                $publicIpAddress = Get-SdnResource -NcUri $NcUri.AbsoluteUri -Credential $Credential -ResourceRef $publicIpRef
                if ($publicIpAddress) {
                    [void]$arrayList.Add(
                        [PSCustomObject]@{
                            IPConfigResourceRef      = $ipConfig.resourceRef
                            IPConfigPrivateIPAddress = $ipConfig.properties.privateIPAddress
                            PublicIPResourceRef      = $publicIpAddress.resourceRef
                            PublicIPAddress          = $publicIpAddress.properties.ipAddress
                        }
                    )
                }
            }
        }

        return $arrayList
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}