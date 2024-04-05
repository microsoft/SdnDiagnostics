function Get-CommonConfigState {
    <#
        .SYNOPSIS
            Retrieves a common set of configuration details that is collected on any role, regardless of the role.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    $currentErrorActionPreference = $ErrorActionPreference
    $ProgressPreference = 'SilentlyContinue'
    $ErrorActionPreference = 'Ignore'

    try {
        [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath "Common"

        "Collect general configuration state details" | Trace-Output -Level:Verbose
        if (-NOT (Initialize-DataCollection -FilePath $OutputDirectory.FullName -MinimumMB 100)) {
            "Unable to initialize environment for data collection" | Trace-Output -Level:Error
            return
        }

        # Gather general configuration details from all nodes
        "Gathering system details" | Trace-Output -Level:Verbose
        Get-Service | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType txt -Format List
        Get-Process | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType txt -Format List
        Get-Volume | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType txt -Format Table
        Get-ComputerInfo | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType txt

        # gather network related configuration details
        "Gathering network details" | Trace-Output -Level:Verbose
        Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{n="ProcessName";e={(Get-Process -Id $_.OwningProcess -ErrorAction $ErrorActionPreference).ProcessName}} `
        | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetTCPConnection' -FileType csv
        Get-NetIPInterface | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType txt -Format Table
        Get-NetNeighbor -IncludeAllCompartments | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType txt -Format Table
        Get-NetConnectionProfile | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType txt -Format Table
        Get-NetRoute -AddressFamily IPv4 -IncludeAllCompartments | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType txt -Format Table
        ipconfig /allcompartments /all | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'ipconfig_allcompartments' -FileType txt

        Get-NetAdapter | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType txt -Format Table
        Get-NetAdapterSriov | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType txt -Format Table
        Get-NetAdapterSriovVf | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType txt -Format Table
        Get-NetAdapterRsc | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType txt -Format Table
        Get-NetAdapterHardwareInfo | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType txt -Format Table
        netsh winhttp show proxy | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'netsh_winhttp_show_proxy' -FileType txt

        $netAdapter = Get-NetAdapter
        if ($netAdapter) {
            $netAdapter | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetAdapter' -FileType txt -Format List
            $netAdapter | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetAdapter' -FileType json

            $netAdapterRootDir = New-Item -Path (Join-Path -Path $OutputDirectory.FullName -ChildPath 'NetAdapter') -ItemType Directory -Force
            $netAdapter | ForEach-Object {
                $_ | Get-NetAdapterAdvancedProperty | Export-ObjectToFile -FilePath $netAdapterRootDir.FullName -Prefix $_.Name -Name -FileType json
                $_ | Get-NetAdapterBinding | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix $_.Name -FileType json
                $_ | Get-NetAdapterChecksumOffload | Export-ObjectToFile -FilePath $netAdapterRootDir.FullName -Prefix $_.Name -FileType json
                $_ | Get-NetAdapterHardwareInfo -ErrorAction $ErrorActionPreference | Export-ObjectToFile -FilePath $netAdapterRootDir.FullName -Prefix $_.Name -FileType json
                $_ | Get-NetAdapterRsc -ErrorAction $ErrorActionPreference | Export-ObjectToFile -FilePath $netAdapterRootDir.FullName -Prefix $_.Name -FileType json
                $_ | Get-NetAdapterSriov -ErrorAction $ErrorActionPreference | Export-ObjectToFile -FilePath $netAdapterRootDir.FullName -Prefix $_.Name -FileType json
                $_ | Get-NetAdapterStatistics | Export-ObjectToFile -FilePath $netAdapterRootDir.FullName -Prefix $_.Name -FileType json
            }
        }

        # Gather DNS client settings
        Get-DnsClient | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType txt -Format List
        Get-DnsClientCache | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType txt -Format List
        Get-DnsClientServerAddress | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType txt -Format List
        Get-DnsClientGlobalSetting | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType txt -Format List
        Get-DnsClientNrptGlobal | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType txt -Format List
        Get-DnsClientNrptPolicy | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType txt -Format List
        Get-DnsClientNrptRule | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType txt -Format List
        Get-DnsClientServerAddress | Export-ObjectToFile -FilePath $OutputDirectory.FullName -FileType txt -Format List

        # gather the certificates configured on the system
        $certificatePaths = @('Cert:\LocalMachine\My','Cert:\LocalMachine\Root')
        foreach ($path in $certificatePaths) {
            $fileName = $path.Replace(':','').Replace('\','_')
            Get-SdnCertificate -Path $path | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name "Get-SdnCertificate_$($fileName)" -FileType csv
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }

    $ProgressPreference = 'Continue'
    $ErrorActionPreference = $currentErrorActionPreference
}
