# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Export-RegistryKeyConfigDetails {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String[]]$Path,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    try {
        # create the OutputDirectory if does not already exist
        if(!(Test-Path -Path $OutputDirectory.FullName -PathType Container)){
            $null = New-Item -Path $OutputDirectory.FullName -ItemType Directory -Force
        }

        foreach($regKeyPath in $Path){
            "Enumerating the registry key paths for {0}" -f $regkeyPath | Trace-Output -Level:Verbose

            $regKeyDirectories = @()
            $regKeyDirectories += Get-ChildItem -Path $regKeyPath -ErrorAction SilentlyContinue
            $regKeyDirectories += Get-ChildItem -Path $regKeyPath -Recurse -ErrorAction SilentlyContinue
            $regKeyDirectories = $regKeyDirectories | Sort-Object -Unique
    
            [System.String]$filePath = "{0}\Registry_{1}.txt" -f $OutputDirectory.FullName, $($regKeyPath.Replace(':','').Replace('\','_'))
            foreach($obj in $RegKeyDirectories){
                "Scanning {0}" -f $obj.PsPath | Trace-Output -Level:Verbose
                try {
                    $properties = Get-ItemProperty -Path $obj.PSPath -ErrorAction Stop
                }
                catch {
                    "Unable to return results from {0}`n`t{1}" -f $obj.PSPath, $_.Exception | Trace-Output -Level:Warning
                    continue
                }

                $properties | Out-File -FilePath $filePath -Encoding utf8 -Append

                # if the registry key item is referencing a dll, then lets get the dll properties so we can see the version and file information
                if($properties.Path -like "*.dll" -or $properties.Path -like "*.exe"){
                    "Getting file properties for {0}" -f $properties.Path | Trace-Output -Level:Verbose
                    [System.String]$fileName = "FileInfo_{0}" -f $($properties.Path.Replace(':','').Replace('\','_').Replace('.','_'))
                    Get-Item -Path $properties.Path | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name $fileName -FileType txt -Format List
                }
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-GeneralConfigurationState {
    <#
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    $ProgressPreference = 'SilentlyContinue'

    try {
        # create the OutputDirectory if does not already exist
        if(!(Test-Path -Path $OutputDirectory.FullName -PathType Container)){
            $null = New-Item -Path $OutputDirectory.FullName -ItemType Directory -Force
        }

        # Gather general configuration details from all nodes
        "Gathering network and system properties" | Trace-Output -Level:Verbose
        Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{n="ProcessName";e={(Get-Process -Id $_.OwningProcess).ProcessName}} `
            | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetTCPConnection' -FileType csv
        Get-Service | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-Service' -FileType txt -Format List
        Get-Process | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-Process' -FileType txt -Format List
        Get-Volume | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-Volume' -FileType txt -Format Table
        Get-ComputerInfo | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-ComputerInfo' -FileType txt
        Get-NetIPInterface | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetIPInterface' -FileType txt -Format Table
        Get-NetNeighbor -IncludeAllCompartments | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetNeighbor' -FileType txt -Format Table
        Get-NetRoute -AddressFamily IPv4 -IncludeAllCompartments | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetRoute' -FileType txt -Format Table
        ipconfig /allcompartments /all | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'ipconfig_allcompartments' -FileType txt

        "Gathering network adapter properties" | Trace-Output -Level:Verbose
        Get-NetAdapter | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetAdapter' -FileType txt -Format Table
        $outputDir = New-Item -Path (Join-Path -Path $OutputDirectory.FullName -ChildPath 'NetAdapter') -ItemType Directory -Force
        foreach($adapter in Get-NetAdapter){
            Get-NetAdapter -Name $adapter.Name | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix $adapter.Name -Name 'Get-NetAdapter' -FileType txt -Format List
            Get-NetAdapterAdvancedProperty -Name $adapter.Name `
                | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix $adapter.Name -Name 'Get-NetAdapterAdvancedProperty' -FileType txt -Format List
        }

        # Gather DNS client settings
        "Gathering DNS client properties" | Trace-Output -Level:Verbose
        $outputDir = New-Item -Path (Join-Path -Path $OutputDirectory.FullName -ChildPath 'DnsClient') -ItemType Directory -Force
        $dnsCommands = Get-Command -Verb Get -Module DnsClient
        foreach($cmd in $dnsCommands.Name){
            Invoke-Expression -Command $cmd -ErrorAction SilentlyContinue | Export-ObjectToFile -FilePath $outputDir.FullName -Name $cmd.ToString() -FileType txt -Format List
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }

    $ProgressPreference = 'Continue'
}
