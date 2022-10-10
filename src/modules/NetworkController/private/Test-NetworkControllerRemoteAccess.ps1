# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-NetworkControllerRemoteAccess {
    <#
    .SYNOPSIS
        Validate if all Network Controller Nodes can be remote accessed via PowerShell and Admin share can be accessed.
    .DESCRIPTION
        The command run a list of validation to ensure cert update can be run successfully.
        Validate if all Network Controller Nodes can be remote accessed via PowerShell and Admin share can be accessed.
        It returns $true if all validation passed. Otherwise return $false

    .PARAMETER NetworkController
        Specifies one of the Network Controller VM name.

    .EXAMPLE
        Test-NetworkControllerRemoteAccess -NetworkController nc1 -Verbose
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $NetworkController,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $psRemoteAccess = Invoke-Command -ComputerName $NetworkController -ScriptBlock{HostName} -ErrorAction Ignore -Credential $Credential
        if($null -eq $psRemoteAccess)
        {
            Trace-Output "The Network Controller: [$NetworkController] cannot be accessed remotely via PowerShell" -Level:Error
            return $false
        }

        Trace-Output "The Network Controller: [$NetworkController] can be accessed remotely via PowerShell" -Level:Verbose

        $NcInfraInfo = Get-SdnNetworkControllerInfoOffline -NetworkController $NetworkController -Credential $Credential

        $NcNodeFQDN = $NcInfraInfo.NodeList.IpAddressOrFQDN

        if($($NcInfraInfo.ClusterCredentialType) -eq "Windows")
        {
            # If auth type is Windows/Kerberos, the script need to run on Network Controller VM
            $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName + "." + (get-ciminstance win32_computersystem).Domain
            if($NcNodeFQDN -contains $NodeFQDN){
                Trace-Output "The ClusterCredentialType is Windows and currently running on Network Controller" -Level:Verbose
            }else{
                Trace-Output "The ClusterCredentialType is Windows. The script need to run on Network Controller directly" -Level:Error
                return $false
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
