# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-SdnKIServerHostId {
    <#
    .SYNOPSIS
        Queries the NCHostAgent HostID registry key value across the hypervisor hosts to ensure the HostID matches known InstanceID results from NC Servers API.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    .EXAMPLE
        PS> Test-SdnKIServerHostId
    .EXAMPLE
        PS> Test-SdnKIServerHostId -Credential (Get-Credential) -NcRestCredential (Get-Credential)
    .EXAMPLE
        PS> Test-SdnKIServerHostId -ComputerName 'Server01','Server02' -Credential (Get-Credential) -NcRestCredential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Uri]$NcUri = $Global:SdnDiagnostics.EnvironmentInfo.NcUrl,

        [Parameter(Mandatory = $false)]
        [System.String[]]$ComputerName = $global:SdnDiagnostics.EnvironmentInfo.Host,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        "Validating Server HostID registry matches known InstanceIDs from Network Controller Servers API." | Trace-Output

        if($null -eq $NcUri){
            throw New-Object System.NullReferenceException("Please specify NcUri parameter or execute Get-SdnInfrastructureInfo to populate environment details")
        }

        if($null -eq $ComputerName){
            throw New-Object System.NullReferenceException("Please specify ComputerName parameter or execute Get-SdnInfrastructureInfo to populate environment details")
        }

        # if Credential parameter not defined, check to see if global cache is populated
        if(!$PSBoundParameters.ContainsKey('Credential')){
            if($Global:SdnDiagnostics.Credential){
                $Credential = $Global:SdnDiagnostics.Credential
            }    
        }

        # if NcRestCredential parameter not defined, check to see if global cache is populated
        if(!$PSBoundParameters.ContainsKey('NcRestCredential')){
            if($Global:SdnDiagnostics.NcRestCredential){
                $NcRestCredential = $Global:SdnDiagnostics.NcRestCredential
            }    
        }

        $issueDetected = $false
        $arrayList = [System.Collections.ArrayList]::new()

        $scriptBlock = {
            $result = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters' -Name 'HostId' -ErrorAction SilentlyContinue
            return $result.HostID
        }

        $servers = Get-SdnResource -NcUri $NcUri.AbsoluteUri -ResourceType Servers -Credential $NcRestCredential
        $hostId = Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scriptBlock -AsJob -PassThru
        foreach($id in $hostId){
            if($id -inotin $servers.instanceId){
                "{0}'s HostID {1} does not match known instanceID results in Network Controller Server REST API" -f $id.PSComputerName, $id | Trace-Output -Level:Warning
                $issueDetected = $true

                $object = [PSCustomObject]@{
                    HostID = $id
                    Computer = $id.PSComputerName
                }

                [void]$arrayList.Add($object)
            }
            else {
                "{0}'s HostID {1} matches known InstanceID in Network Controller Server REST API" -f $id.PSComputerName, $id | Trace-Output -Level:Verbose
            }
        }

        return [PSCustomObject]@{
            Result = $issueDetected
            Properties = $arrayList
        }

    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
