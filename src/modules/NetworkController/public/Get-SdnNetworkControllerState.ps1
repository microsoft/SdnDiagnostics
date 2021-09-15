function Get-SdnNetworkControllerState {
    <#
    .SYNOPSIS
        Gathers the IMOS dump files from each of the Network Controllers
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER ComputerName
        The computer name(s) of the Network Controllers that the IMOS dump files need to be collected from
    .PARAMETER OutputDirectory
        Directory location to save results. By default it will create a new sub-folder called NetworkControllerState that the files will be copied to
    .PARAMETER ExecutionTimeout
        Specify the execution timeout (seconds) on how long you want to wait for operation to complete before cancelling operation
        Default: 300
    .EXAMPLE 
        Get-SdnNcImosDumpFiles -NcUri "https://nc.contoso.com" -ComputerName $NetworkControllers -OutputDirectory "C:\Temp\CSS_SDN"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $true)]
        [System.String[]]$ComputerName,

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
        $config = Get-SdnRoleConfiguration -Role:NetworkController
        [System.IO.FileInfo]$netControllerStatePath = $config.properties.netControllerStatePath
        [System.IO.FileInfo]$outputDir = Join-Path -Path $OutputDirectory.FullName -ChildPath 'NetworkControllerState'

        if (!(Test-Path -Path $outputDir.FullName -PathType Container)) {
            $null = New-Item -Path $outputDir.FullName -ItemType Directory -Force
        }

        $scriptBlock = {
            try {
                if (Test-Path -Path $using:netControllerStatePath.FullName -PathType Container) {
                    Get-Item -Path $using:netControllerStatePath.FullName | Remove-Item -Recurse -Confirm:$false -Force -ErrorAction SilentlyContinue
                }
    
                $null = New-Item -Path $using:netControllerStatePath.FullName -ItemType Container -Force
            }
            catch {
                $_ | Write-Error
            }
        }

        # invoke scriptblock to clean up any stale NetworkControllerState files
        Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock $scriptBlock -Credential $Credential

        # invoke the call to generate the files
        # once the operation completes and returns true, then enumerate through the ComputerNames defined to collect the files
        $result = Invoke-SdnNetworkControllerStateDump -NcUri $NcUri.AbsoluteUri -Credential $NcRestCredential -ExecutionTimeOut $ExecutionTimeOut
        if ($result) {
            foreach ($obj in $ComputerName) {
                Copy-FileFromPSRemoteSession -Path "$($config.properties.netControllerStatePath)\*" -ComputerName $obj -Destination $outputDir.FullName
            }
        }        
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
