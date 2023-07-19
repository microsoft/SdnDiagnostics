function Add-SdnDiagTraceMapping {
    param (
        [Parameter(Mandatory=$true)]
        [string]$MacAddress,

        [Parameter(Mandatory=$true)]
        [string]$InfraHost,

        [Parameter(Mandatory=$false)]
        [string]$PortId,

        [Parameter(Mandatory=$false)]
        [string]$PortName,

        [Parameter(Mandatory=$false)]
        [string]$NicName,

        [Parameter(Mandatory=$false)]
        [string]$VmName,

        [Parameter(Mandatory=$false)]
        [string]$VmInternalId,

        [Parameter(Mandatory=$false)]
        [string[]]$PrivateIpAddress
    )

    $cacheName = 'TraceMapping'
    $mapping = @{
        MacAddress = $MacAddress
        PortId = $PortId
        PortName = $PortName
        NicName = $NicName
        VmName = $VmName
        VmInternalId = $VmInternalId
        InfraHost = $InfraHost
        PrivateIpAddress = $PrivateIpAddress
    }

    if (!$Script:SdnDiagnostics_Common.Cache.ContainsKey($cacheName)) {
        $Script:SdnDiagnostics_Common.Cache.Add($cacheName, @{})
    }

    if (!$Script:SdnDiagnostics_Common.Cache[$cacheName].ContainsKey($InfraHost.ToLower())) {
        $Script:SdnDiagnostics_Common.Cache[$cacheName].Add($InfraHost.ToLower(), @{})
    }

    $Script:SdnDiagnostics_Common.Cache[$cacheName][$InfraHost.ToLower()][$MacAddress] += $mapping
}
