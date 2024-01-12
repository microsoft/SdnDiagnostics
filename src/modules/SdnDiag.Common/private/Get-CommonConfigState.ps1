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
    $ErrorActionPreference = 'SilentlyContinue'

    try {
        [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath "Common"

        "Collect general configuration state details" | Trace-Output
        if (-NOT (Initialize-DataCollection -FilePath $OutputDirectory.FullName -MinimumMB 100)) {
            "Unable to initialize environment for data collection" | Trace-Output -Level:Error
            return
        }

        # Gather general configuration details from all nodes
        "Gathering system details" | Trace-Output -Level:Verbose
        Get-Service | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-Service' -FileType txt -Format List
        Get-Process | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-Process' -FileType txt -Format List
        Get-Volume | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-Volume' -FileType txt -Format Table
        Get-ComputerInfo | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-ComputerInfo' -FileType txt

        # gather network related configuration details
        "Gathering network details" | Trace-Output -Level:Verbose
        Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{n="ProcessName";e={(Get-Process -Id $_.OwningProcess -ErrorAction $ErrorActionPreference).ProcessName}} `
        | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetTCPConnection' -FileType csv
        Get-NetIPInterface | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetIPInterface' -FileType txt -Format Table
        Get-NetNeighbor -IncludeAllCompartments | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetNeighbor' -FileType txt -Format Table
        Get-NetConnectionProfile | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetConnectionProfile' -FileType txt -Format Table
        Get-NetRoute -AddressFamily IPv4 -IncludeAllCompartments | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetRoute' -FileType txt -Format Table
        ipconfig /allcompartments /all | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'ipconfig_allcompartments' -FileType txt

        Get-NetAdapter | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetAdapter' -FileType txt -Format Table
        Get-NetAdapterSriov | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetAdapterSriov' -FileType txt -Format Table
        Get-NetAdapterSriovVf | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetAdapterSriovVf' -FileType txt -Format Table
        Get-NetAdapterRsc | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetAdapterRsc' -FileType txt -Format Table
        Get-NetAdapterHardwareInfo | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetAdapterHardwareInfo' -FileType txt -Format Table
        netsh winhttp show proxy | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'netsh_winhttp_show_proxy' -FileType txt

        $outputDir = New-Item -Path (Join-Path -Path $OutputDirectory.FullName -ChildPath 'NetAdapter') -ItemType Directory -Force
        foreach($adapter in Get-NetAdapter){
            Get-NetAdapter -Name $adapter.Name | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix $adapter.Name -Name 'Get-NetAdapter' -FileType txt -Format List
            Get-NetAdapterSriov -Name $adapter.Name -ErrorAction $ErrorActionPreference | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix $adapter.Name -Name 'Get-NetAdapterSriov' -FileType txt -Format List
            Get-NetAdapterRsc -Name $adapter.Name -ErrorAction $ErrorActionPreference | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix $adapter.Name -Name 'Get-NetAdapterRsc' -FileType txt -Format List
            Get-NetAdapterHardwareInfo -Name $adapter.Name -ErrorAction $ErrorActionPreference | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix $adapter.Name -Name 'Get-NetAdapterHardwareInfo' -FileType txt -Format List
            Get-NetAdapterAdvancedProperty -Name $adapter.Name `
                | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix $adapter.Name -Name 'Get-NetAdapterAdvancedProperty' -FileType txt -Format List
        }

        # Gather DNS client settings
        Get-DnsClient | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-DnsClient' -FileType txt -Format List
        Get-DnsClientCache | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-DnsClientCache' -FileType txt -Format List
        Get-DnsClientDohServerAddress | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-DnsClientDohServerAddress' -FileType txt -Format List
        Get-DnsClientGlobalSetting | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-DnsClientGlobalSetting' -FileType txt -Format List
        Get-DnsClientNrptGlobal | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-DnsClientNrptGlobal' -FileType txt -Format List
        Get-DnsClientNrptPolicy | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-DnsClientNrptPolicy' -FileType txt -Format List
        Get-DnsClientNrptRule | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-DnsClientNrptRule' -FileType txt -Format List
        Get-DnsClientServerAddress | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-DnsClientServerAddress' -FileType txt -Format List

        # gather the certificates configured on the system
        $certificatePaths = @('Cert:\LocalMachine\My','Cert:\LocalMachine\Root')
        foreach ($path in $certificatePaths) {
            $fileName = $path.Replace(':','').Replace('\','_')
            Get-SdnCertificate -Path $path | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name "Get-SdnCertificate_$($fileName)" -FileType csv
        }
    }
    catch {
        $_ | Trace-Exception
    }

    $ProgressPreference = 'Continue'
    $ErrorActionPreference = $currentErrorActionPreference
}
