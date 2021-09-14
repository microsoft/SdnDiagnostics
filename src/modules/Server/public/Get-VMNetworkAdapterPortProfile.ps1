function Get-VMNetworkAdapterPortProfile {
    <#
    #>

    [CmdletBinding(DefaultParameterSetName = 'SingleVM')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'SingleVM')]
        [System.String]$VMName,

        [Parameter(Mandatory = $true, ParameterSetName = 'AllVMs')]
        [Switch]$AllVMs,

        [Parameter(Mandatory = $false, ParameterSetName = 'SingleVM')]
        [Parameter(Mandatory = $false, ParameterSetName = 'AllVMs')]
        [System.Guid]$PortProfileFeatureId = '9940cd46-8b06-43bb-b9d5-93d50381fd56'
    )

    try {

        if ($null -eq (Get-Module -Name Hyper-V)) {
            Import-Module -Name Hyper-V -Force
        }

        $arrayList = [System.Collections.ArrayList]::new()

        if ($AllVMs) {
            $netAdapters = Get-VMNetworkAdapter -All
        }
        else {
            $netAdapters = Get-VMNetworkAdapter -VMName $VMName
        }

        foreach ($adapter in $netAdapters | Where-Object { $_.IsManagementOs -eq $false }) {
            $currentProfile = Get-VMSwitchExtensionPortFeature -FeatureId $PortProfileFeatureId -VMNetworkAdapter $adapter
            $portId = (Get-VMSwitchExtensionPortData -VMNetworkAdapter $adapter)[0].data.deviceid
            if ($null -eq $currentProfile) {
                "{0} does not have a port profile" -f $adapter.Name | Trace-Output -Level:Warning
            }
            else {
                $object = [PSCustomObject]@{
                    VMName     = $adapter.VMName
                    Name       = $adapter.Name
                    MacAddress = $adapter.MacAddress
                    PortId     = $portId
                    ProfileId  = $currentProfile.SettingData.ProfileId
                    Data       = $currentProfile.SettingData.ProfileData
                }

                [void]$arrayList.Add($object)
            }
        }

        return ($arrayList | Sort-Object -Property Name)
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
