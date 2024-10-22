function Get-SdnNetworkInterfaceOutboundPublicIPAddress {
    <#
    .SYNOPSIS
        Gets the outbound public IP address that is used by a network interface.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER ResourceId
        Specifies the unique identifier for the networkinterface resource.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    .EXAMPLE
        PS> Get-SdnNetworkInterfaceOutboundPublicIPAddress -NcUri "https://nc.contoso.com" -ResourceId '8f9faf0a-837b-43cd-b4bf-dbe996993514'
    .EXAMPLE
        PS> Get-SdnNetworkInterfaceOutboundPublicIPAddress -NcUri "https://nc.contoso.com" -ResourceId '8f9faf0a-837b-43cd-b4bf-dbe996993514' -Credential (Get-Credential)
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [uri]$NcUri,

        [Parameter(Mandatory = $true)]
        [System.String]$ResourceId,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate
    )

    $arrayList = [System.Collections.ArrayList]::new()

    $ncRestParams = @{
        NcUri = $NcUri
    }
    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $ncRestParams.Add('NcRestCredential', $NcRestCredential)
        }
    }

    try {
        $networkInterface = Get-SdnResource @ncRestParams -Resource:NetworkInterfaces | Where-Object { $_.resourceId -ieq $ResourceId }
        if ($null -eq $networkInterface) {
            throw New-Object System.NullReferenceException("Unable to locate network interface within Network Controller")
        }

        foreach ($ipConfig in $networkInterface.properties.ipConfigurations) {
            $publicIpRef = Get-PublicIpReference @ncRestParams -IpConfiguration $ipConfig
            if ($publicIpRef) {
                $publicIpAddress = Get-SdnResource @ncRestParams -ResourceRef $publicIpRef
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
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
