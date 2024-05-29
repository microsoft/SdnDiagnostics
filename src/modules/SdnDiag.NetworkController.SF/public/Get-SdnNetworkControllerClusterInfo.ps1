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
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-NetworkController" -FileType txt

        Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock { Get-NetworkControllerNode } -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-NetworkControllerNode" -FileType txt

        Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock { Get-NetworkControllerCluster } -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-NetworkControllerCluster" -FileType txt

        Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock { Get-NetworkControllerReplica } -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-NetworkControllerReplica" -FileType txt

        Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock {  Get-SdnServiceFabricClusterConfig -Uri GlobalConfiguration} -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "NetworkControllerGlobalConfiguration" -FileType txt -Format Table

        Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock {  Get-SdnServiceFabricClusterConfig -Uri ClusterConfiguration} -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "NetworkControllerClusterConfiguration" -FileType txt -Format Table

        Get-SdnServiceFabricClusterHealth -NetworkController $NetworkController -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-SdnServiceFabricClusterHealth" -FileType txt

        Get-SdnServiceFabricApplicationHealth -NetworkController $NetworkController -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-SdnServiceFabricApplicationHealth" -FileType txt

        Get-SdnServiceFabricClusterManifest -NetworkController $NetworkController -Credential $Credential `
        | Out-File -FilePath "$($outputDir.FullName)\Get-SdnServiceFabricClusterManifest.xml"

        $ncServices = Get-SdnServiceFabricService -NetworkController $NetworkController -Credential $Credential
        $ncServices | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-SdnServiceFabricService" -FileType txt
        foreach ($service in $ncServices) {
            Get-SdnServiceFabricReplica -NetworkController $NetworkController -Credential $Credential -ServiceName $service.ServiceName `
            | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-SdnServiceFabricReplica_$($service.ServiceTypeName)" -FileType txt
        }

        Get-SdnServiceFabricApplication -NetworkController $NetworkController -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-SdnServiceFabricApplication" -FileType json

        Get-SdnServiceFabricNode -NetworkController $NetworkController -Credential $Credential `
        | Export-ObjectToFile -FilePath $outputDir.FullName -Name "Get-SdnServiceFabricNode" -FileType txt

    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
