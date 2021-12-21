function Get-SdnMuxVipConfig {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$VirtualIP
    )

    try {
        $control = Get-MuxDriverControl
        $arrayList = [System.Collections.ArrayList]::new()

        if ($VirtualIP) {
            $statefulVips = Get-SdnMuxStatefulVip -VirtualIp $VirtualIP
        }
        else {
            $statefulVips = Get-SdnMuxStatefulVip
        }

        foreach ($vip in $statefulVips) {
            $vipConfig = New-Object -Type Microsoft.Cloudnet.Slb.Mux.Driver.VipEndpointConfig
            $vipinfo = @{};
            $dips = @{};

            $control.GetVipConfig($vip, [ref]$vipConfig)
            $vipinfo["Protocol"] = $vip.Protocol;
            $vipinfo["Port"] = $vip.Port;
        
            foreach ($dipMapEntry in $vipConfig.DipMap.DipEntries) {						
                $dipInfo = @{};
                $dipInfo["EncapType"]= $dipMapEntry.ReachabilityInfo.EncapType;
                $dipInfo["EncapData"]= $dipMapEntry.ReachabilityInfo.EncapData;
                $dips[$dipMapEntry.DipAddress.IPAddressToString] = $dipInfo;
            }      
           
            $vipInfo["Dips"] = $dips;
        }

        # TO DO
        # build pscustomobject to add to array list and then return results
    
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}