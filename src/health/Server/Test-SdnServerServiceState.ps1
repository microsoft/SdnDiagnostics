function Test-SdnServerServiceState {
    <#
    .SYNOPSIS
        Confirms that critical services for load balancer muxes are running
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers. To specify the local computer, type the computer name, localhost, or a dot (.). When the computer is in a different domain than the user, the fully qualified domain name is required.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user. The user account should be a member of the NCAdmins group.
        Type a user name, such as User01 or Domain01\User01, or enter a PSCredential object generated by the Get-Credential cmdlet. If you type a user name, you're prompted to enter the password.
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String[]]$ComputerName = $Global:SdnDiagnostics.EnvironmentInfo.Host,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $config = Get-SdnRoleConfiguration -Role:Server
        "Validating that {0} service is running for {1} role" -f ($config.properties.services.properties.displayName -join ', '), $config.Name | Trace-Output

        if($null -eq $ComputerName){
            throw New-Object System.NullReferenceException("Please specify ComputerName parameter or execute Get-SdnInfrastructureInfo to populate environment details")
        }

        # if Credential parameter not defined, check to see if global cache is populated
        if(!$PSBoundParameters.ContainsKey('Credential')){
            if($Global:SdnDiagnostics.Credential){
                $Credential = $Global:SdnDiagnostics.Credential
            }    
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

        $serviceStateResults = Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -Scriptblock $scriptBlock
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