# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnInfrastructureInfo {
    <#
    .SYNOPSIS
        Get the SDN infrastructure information from network controller. The function will update the $Global:SdnDiagnostics.EnvironmentInfo variable.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operates.
    .PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER NcRestCredential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnInfrastructureInfo
    .EXAMPLE
        PS> Get-SdnInfrastructureInfo -NetworkController 'NC01' -Credential (Get-Credential) -NcRestCredential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$NetworkController,

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

        if([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.EnvironmentInfo.NcUrl))
        {
            $result = Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock {Get-NetworkController} -Credential $Credential
            $Global:SdnDiagnostics.EnvironmentInfo.NcUrl = "https://$($result.RestName)"
        }
        
        if([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.EnvironmentInfo.NC))
        {
            $Global:SdnDiagnostics.EnvironmentInfo.NC = Get-SdnNetworkController -NetworkController $NetworkController -ServerNameOnly -Credential $Credential
        }

        if([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.EnvironmentInfo.MUX))
        {
            $Global:SdnDiagnostics.EnvironmentInfo.MUX = Get-SdnLoadBalancerMux -NcUri $Global:SdnDiagnostics.EnvironmentInfo.NcUrl -ManagementAddressOnly -Credential $NcRestCredential
        }

        if([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.EnvironmentInfo.Gateway))
        {
            $Global:SdnDiagnostics.EnvironmentInfo.Gateway = Get-SdnGateway -NcUri $Global:SdnDiagnostics.EnvironmentInfo.NcUrl -ManagementAddressOnly -Credential $NcRestCredential
        }

        if([System.String]::IsNullOrEmpty($Global:SdnDiagnostics.EnvironmentInfo.Host))
        {
            #The credential for NC REST API could be different from NC Admin credential. Caller need to determine the credential to be used. 
            $Global:SdnDiagnostics.EnvironmentInfo.Host = Get-SdnServer -NcUri $Global:SdnDiagnostics.EnvironmentInfo.NcUrl -ManagementAddressOnly -Credential $NcRestCredential
        }

        return $Global:SdnDiagnostics.EnvironmentInfo
    } 
    catch {
        # Remove any cached info in case of exception as the cached info might be incorrect
        $Global:SdnDiagnostics.EnvironmentInfo.NcUrl = $null
        $Global:SdnDiagnostics.EnvironmentInfo.NC = $null
        $Global:SdnDiagnostics.EnvironmentInfo.MUX = $null
        $Global:SdnDiagnostics.EnvironmentInfo.Gateway = $null
        $Global:SdnDiagnostics.EnvironmentInfo.Host = $null
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
