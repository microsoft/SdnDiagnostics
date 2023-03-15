function Test-GatewayServiceState {
    <#
    .SYNOPSIS
        Confirms that critical services for gateway are running
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Test-GatewayServiceState
    .EXAMPLE
        PS> Test-GatewayServiceState -ComputerName 'Gateway01','Gateway02'
    .EXAMPLE
        PS> Test-GatewayServiceState -ComputerName 'Gateway01','Gateway02' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()
    $sdnHealthObject.Result = 'PASS'
    $arrayList = [System.Collections.ArrayList]::new()

    try {
        $config = Get-SdnModuleConfiguration -Role:Gateway
        "Validating that {0} service is running for {1} role" -f ($config.properties.services.properties.displayName -join ', '), $config.Name | Trace-Output

        $scriptBlock = {
            param([Parameter(Position = 0)][System.Object]$param1)

            $serviceArrayList = [System.Collections.ArrayList]::new()
            foreach($service in $($param1.properties.services.name)){
                $result = Get-Service -Name $service -ErrorAction SilentlyContinue
                if($result){
                    [void]$serviceArrayList.Add($result)
                }
            }

            return $serviceArrayList
        }

        $serviceStateResults = Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -Scriptblock $scriptBlock -ArgumentList $config
        foreach($result in $serviceStateResults){
            if($result.Status -ine 'Running'){
                [void]$arrayList.Add($result)
                $sdnHealthObject.Result = 'FAIL'

                "{0} is {1} on {2}" -f $result.Name, $result.Status, $result.PSComputerName | Trace-Output -Level:Warning
            }
            else {
                "{0} is {1} on {2}" -f $result.Name, $result.Status, $result.PSComputerName | Trace-Output -Level:Verbose
            }
        }

        $sdnHealthObject.Properties = $arrayList
        return $sdnHealthObject
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
