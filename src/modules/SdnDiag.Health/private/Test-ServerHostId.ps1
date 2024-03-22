function Test-ServerHostId {
    <#
    .SYNOPSIS
        Queries the NCHostAgent HostID registry key value across the hypervisor hosts to ensure the HostID matches known InstanceID results from NC Servers API.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()
    $array = @()

    try {
        "Validating Server HostID registry matches known InstanceIDs from Network Controller Servers API." | Trace-Output

        $scriptBlock = {
            $result = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters' -Name 'HostId' -ErrorAction SilentlyContinue
            return $result.HostID
        }

        $servers = Get-SdnResource -NcUri $SdnEnvironmentObject.NcUrl.AbsoluteUri -Resource $SdnEnvironmentObject.Role.ResourceName -Credential $NcRestCredential
        $hostId = Invoke-PSRemoteCommand -ComputerName $SdnEnvironmentObject.ComputerName -Credential $Credential -ScriptBlock $scriptBlock -AsJob -PassThru
        foreach($id in $hostId){
            if($id -inotin $servers.instanceId){
                "{0}'s HostID {1} does not match known instanceID results in Network Controller Server REST API" -f $id.PSComputerName, $id | Trace-Output -Level:Error
                $sdnHealthObject.Result = 'FAIL'
                $sdnHealthObject.Remediation += "Update the HostId registry key on $($id.PSComputerName) to match the InstanceId of the Server resource in Network Controller"

                $object = [PSCustomObject]@{
                    HostID = $id
                    Computer = $id.PSComputerName
                }

                $array += $object
            }
            else {
                "{0}'s HostID {1} matches known InstanceID in Network Controller Server REST API" -f $id.PSComputerName, $id | Trace-Output -Level:Verbose
            }
        }

        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
    }
}
