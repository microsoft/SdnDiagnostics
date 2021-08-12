function Test-ServerServiceState {
    <#
    .SYNOPSIS
        Confirms that critical services for load balancer muxes are running
    #>
    
    try {
        $config = Get-SdnRoleConfiguration -Role:Server
        "Validating that {0} service is running for {1} role" -f ($config.properties.services.properties.displayName -join ', '), $config.Name | Trace-Output

        $servers = $SdnDiagnostics.EnvironmentInfo.Host
        
        $credential = [System.Management.Automation.PSCredential]::Empty
        if($Global:SdnDiagnostics.Credential){
            $credential = $Global:SdnDiagnostics.Credential
        }

        $status = 'Success'
        $arrayList = [System.Collections.ArrayList]::new()

        $scriptBlock = {
            $serviceArrayList = [System.Collections.ArrayList]::new()
            foreach($service in $($using:config.properties.services.name)){
                $result = Get-Service -Name $service -ErrorAction SilentlyContinue
                if($result){
                    [void]$serviceArrayList.Add($result)
                }
            }

            return $serviceArrayList
        }

        $serviceStateResults = Invoke-PSRemoteCommand -ComputerName $servers -Credential $credential -Scriptblock $scriptBlock
        foreach($result in $serviceStateResults){
            if($result.Status -ine 'Running'){
                [void]$arrayList.Add($result)
                $status = 'Failure'

                "{0} is {1} on {2}" -f $result.Name, $result.Status, $result.PSComputerName | Trace-Output -Level:Warning
            }
            else {
                "{0} is {1} on {2}" -f $result.Name, $result.Status, $result.PSComputerName | Trace-Output -Level:Verbose
            }
        }

        return [PSCustomObject]@{
            Status = $status
            Properties = $arrayList
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}