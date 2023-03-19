function Test-ServiceState {
    <#
    .SYNOPSIS
        Confirms that critical services for gateway are running
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER Service
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String[]]$Name,

        [Parameter(Mandatory = $true)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()
    $arrayList = [System.Collections.ArrayList]::new()
    $serviceStateResults = @()

    try {
        "Validating {0} service state for {1}" -f ($Name -join ', '), ($ComputerName -join ', ') | Trace-Output

        $scriptBlock = {
            param([Parameter(Position = 0)][String]$param1)

            $result = Get-Service -Name $param1 -ErrorAction SilentlyContinue
            return $result
        }

        foreach ($service in $Name) {
            $serviceStateResults += Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -Scriptblock $scriptBlock -ArgumentList $service
        }

        foreach($result in $serviceStateResults){
            [void]$arrayList.Add($result)

            if($result.Status -ine 'Running'){
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
