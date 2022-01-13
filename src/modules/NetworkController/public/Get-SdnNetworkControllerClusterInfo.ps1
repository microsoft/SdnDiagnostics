# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnNetworkControllerClusterInfo {
    <#
    .SYNOPSIS
        Gather the Network Controller cluster wide info from one of the Network Controller
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER OutputDirectory
        Directory location to save results. It will create a new sub-folder called NetworkControllerClusterInfo that the files will be saved to
    .EXAMPLE
        PS> Get-SdnNetworkControllerClusterInfo
    .EXAMPLE
        PS> Get-SdnNetworkControllerClusterInfo -NetworkController 'NC01' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$NetworkController,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    try {
        [System.IO.FileInfo]$outputDir = Join-Path -Path $OutputDirectory.FullName -ChildPath 'NetworkControllerClusterInfo'

        if (!(Test-Path -Path $outputDir.FullName -PathType Container)) {
            $null = New-Item -Path $outputDir.FullName -ItemType Directory -Force
        }

        Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock { Get-NetworkController } -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "GetNetworkController" -FileType txt

        Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock { Get-NetworkControllerNode } -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "GetNetworkControllerNode" -FileType txt

        Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock { Get-NetworkControllerReplica } -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "GetNetworkControllerReplica" -FileType txt

        Get-SdnServiceFabricClusterHealth -NetworkController $NetworkController -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "ServiceFabricClusterHealth" -FileType txt

        Get-SdnServiceFabricApplicationHealth -NetworkController $NetworkController -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "ServiceFabricApplicationHealth" -FileType txt

    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
