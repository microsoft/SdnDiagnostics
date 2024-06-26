function Get-SdnNetworkControllerState {
    <#
    .SYNOPSIS
        Gathers the Network Controller State dump files (IMOS) from each of the Network Controllers
    .PARAMETER NetworkController
        The computer name of the Network Controller used to retrieve Infrastructure Info and trigger IMOS generation.
    .PARAMETER OutputDirectory
        Directory location to save results. By default it will create a new sub-folder called NetworkControllerState that the files will be copied to
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
	.PARAMETER NcRestCredential
		Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    .PARAMETER ExecutionTimeout
        Specify the execution timeout (seconds) on how long you want to wait for operation to complete before cancelling operation. If omitted, defaults to 300 seconds.
    .EXAMPLE
        PS> Get-SdnNcImosDumpFiles -NcUri "https://nc.contoso.com" -NetworkController $NetworkControllers -OutputDirectory "C:\Temp\CSS_SDN"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$NetworkController,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [int]$ExecutionTimeOut = 300
    )
    try {
        "Collecting In Memory Object State (IMOS) for Network Controller" | Trace-Output
        $config = Get-SdnModuleConfiguration -Role:NetworkController
        [System.IO.FileInfo]$netControllerStatePath = $config.properties.netControllerStatePath
        [System.IO.FileInfo]$outputDir = Join-Path -Path $OutputDirectory.FullName -ChildPath 'NetworkControllerState'

        if (!(Test-Path -Path $outputDir.FullName -PathType Container)) {
            $null = New-Item -Path $outputDir.FullName -ItemType Directory -Force
        }

        $scriptBlock = {
            param([Parameter(Position = 0)][String]$param1)
            try {
                if (Test-Path -Path $param1 -PathType Container) {
                    Get-Item -Path $param1 | Remove-Item -Recurse -Confirm:$false -Force -ErrorAction SilentlyContinue
                }

                $null = New-Item -Path $param1 -ItemType Container -Force
            }
            catch {
                $_ | Write-Error
            }
        }

        $infraInfo = Get-SdnInfrastructureInfo -NetworkController $NetworkController -Credential $Credential -NcRestCredential $NcRestCredential
        # invoke scriptblock to clean up any stale NetworkControllerState files
        Invoke-PSRemoteCommand -ComputerName $infraInfo.NetworkController -Credential $Credential -ScriptBlock $scriptBlock -ArgumentList $netControllerStatePath.FullName

        # invoke the call to generate the files
        # once the operation completes and returns true, then enumerate through the Network Controllers defined to collect the files
        $result = Invoke-SdnNetworkControllerStateDump -NcUri $infraInfo.NcUrl -Credential $NcRestCredential -ExecutionTimeOut $ExecutionTimeOut
        if ($result) {
            foreach ($ncVM in $infraInfo.NetworkController) {
                Copy-FileFromRemoteComputer -Path "$($config.properties.netControllerStatePath)\*" -ComputerName $ncVM -Destination $outputDir.FullName
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
