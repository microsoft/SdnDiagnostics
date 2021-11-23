# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-SdnServerServiceState {
    <#
    .SYNOPSIS
        Confirms that critical services for load balancer muxes are running
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Test-SdnServerServiceState
    .EXAMPLE
        PS> Test-SdnServerServiceState -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Test-SdnServerServiceState -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String[]]$ComputerName = $global:SdnDiagnostics.EnvironmentInfo.Server,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [Switch]$Remediate
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

        $healthInsight = Get-InsightDetail -Id '05fd93bd-1662-472a-b430-70a3117bce81' -Type Health
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

        # perform the remediation
        if ($Remediate) {
            $cachedInsight = Get-SdnDiagCache -Container 'FabricHealth' -Name $MyInvocation.MyCommand
            if ($cachedInsight -and $cachedInsight.Status -ieq 'Failure') {
                foreach ($remediationAction in $healthInsight.Remediation) {
                    switch ($remediationAction.action) {
                        'Start_Service' {
                            foreach ($object in $cachedInsight.Property) {
                                Invoke-PSRemoteCommand -ComputerName $object.PSComputerName -Scriptblock {
                                    Invoke-SdnRemediationAction -Action $using:remediationAction.action -RuntimeParameters @{Name = $using:object.Name}
                                }
                            }
                        }
                    }
                }
            }
            else {
                "No cache identified for {0}. Skipping remediation steps" -f $MyInvocation.MyCommand | Trace-Output
            }
        }

        $serviceStateResults = Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -Scriptblock $scriptBlock
        foreach($result in $serviceStateResults){
            if($result.Status -ine 'Running'){
                [void]$arrayList.Add($result)
                $healthInsight.SetFailure()

                "{0} is {1} on {2}" -f $result.Name, $result.Status, $result.PSComputerName | Trace-Output -Level:Warning
            }
            else {
                "{0} is {1} on {2}" -f $result.Name, $result.Status, $result.PSComputerName | Trace-Output -Level:Verbose
            }
        }

        if ($arrayList) {
            $healthInsight.Property = $arrayList
        }

        Set-SdnDiagCache -Container 'FabricHealth' -Name $MyInvocation.MyCommand -Value $healthInsight
        return $healthInsight
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
