function Test-ServiceState {
    <#
    .SYNOPSIS
        Confirms that critical services for gateway are running
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()
    $array = @()
    $serviceStateResults = @()

    try {
        [string[]]$services = $SdnEnvironmentObject.Role.Properties.Services.Keys
        "Validating {0} service state for {1}" -f ($services -join ', '), ($SdnEnvironmentObject.ComputerName -join ', ') | Trace-Output

        $scriptBlock = {
            param([Parameter(Position = 0)][String]$param1)

            $result = Get-Service -Name $param1 -ErrorAction SilentlyContinue
            return $result
        }

        foreach ($service in $services) {
            $serviceStateResults += Invoke-PSRemoteCommand -ComputerName $SdnEnvironmentObject.ComputerName -Credential $Credential -Scriptblock $scriptBlock -ArgumentList $service
        }

        foreach($result in $serviceStateResults){
            $array += $result

            if($result.Status -ine 'Running'){
                $sdnHealthObject.Result = 'FAIL'
                $sdnHealthObject.Remediation += "Start $($result.Name) service on $($result.PSComputerName)"

                "{0} is {1} on {2}" -f $result.Name, $result.Status, $result.PSComputerName | Trace-Output -Level:Error
            }
            else {
                "{0} is {1} on {2}" -f $result.Name, $result.Status, $result.PSComputerName | Trace-Output -Level:Verbose
            }
        }

        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
    }
}
