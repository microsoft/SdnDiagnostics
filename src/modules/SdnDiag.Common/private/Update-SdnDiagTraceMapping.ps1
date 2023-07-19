function Update-SdnDiagTraceMapping {
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
        [string[]]$PrivateIpAddress,

        [Parameter(Mandatory=$false)]
        [string[]]$PublicIpAddress
    )

    $cacheName = 'TraceMapping'
    if($Script:SdnDiagnostics_Common.Cache[$cacheName][$InfraHost][$MacAddress]){
        if($PortId){
            $Script:SdnDiagnostics_Common.Cache[$cacheName][$InfraHost][$MacAddress]['PortId'] = $PortId
        }
        if($PortName){
            $Script:SdnDiagnostics_Common.Cache[$cacheName][$InfraHost][$MacAddress]['PortName'] = $PortName
        }
        if($NicName){
            $Script:SdnDiagnostics_Common.Cache[$cacheName][$InfraHost][$MacAddress]['NicName'] = $NicName
        }
        if($VmName){
            $Script:SdnDiagnostics_Common.Cache[$cacheName][$InfraHost][$MacAddress]['VmName'] = $VmName
        }
        if($VmInternalId){
            $Script:SdnDiagnostics_Common.Cache[$cacheName][$InfraHost][$MacAddress]['VmInternalId'] = $VmInternalId
        }
        if($PrivateIpAddress){
            $Script:SdnDiagnostics_Common.Cache[$cacheName][$InfraHost][$MacAddress]['PrivateIpAddress'] = $PrivateIpAddress
        }
    }
}
