function Debug-SdnFabricInfrastructure {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [ArgumentCompleter({
            $possibleValues = Get-ChildItem -Path "$PSScriptRoot\..\..\private\health" -Directory | Select-Object -ExpandProperty Name
            return $possibleValues | ForEach-Object { $_ }
        })]
        [System.String]$Role,

        [Parameter(Mandatory = $false)]
        [ArgumentCompleter({
            $possibleValues = Get-ChildItem -Path "$PSScriptRoot\..\..\private\health" -Recurse | Where-Object {$_.Extension -eq '.ps1'} | Select-Object -ExpandProperty BaseName
            return $possibleValues | ForEach-Object { $_ }
        })]
        [System.String]$ValidationTest
    )

    try {
        $Global:SdnDiagnostics.NcUrl = $NcUri.AbsoluteUri

        if($PSBoundParameters.ContainsKey('Role')){
            $healthValidationScripts = Get-ChildItem -Path "$PSScriptRoot\..\..\private\health\$Role" -Recurse | Where-Object {$_.Extension -eq '.ps1'}
        }
        elseif($PSBoundParameters.ContainsKey('ValidationTest')){
            $healthValidationScripts = Get-ChildItem -Path "$PSScriptRoot\..\..\private\health" -Recurse | Where-Object {$_.BaseName -ieq $ValidationTest}
            if($healthValidationScripts.Count -gt 1){
                throw New-Object System.Exception("Unexpected number of health validations returned")
            }
        }
        else {
            $healthValidationScripts = Get-ChildItem -Path "$PSScriptRoot\..\private\health" -Recurse | Where-Object {$_.Extension -eq '.ps1'}
        }

        if($null -eq $healthValidationScripts){
            throw New-Object System.NullReferenceException("No health validations returned")
        }

        foreach($script in $healthValidationScripts){
            # get the raw content of the script
            $code = Get-Content -Path $script.FullName -Raw

            # list all the functions in ps1 using language namespace parser
            $functionName = [Management.Automation.Language.Parser]::ParseInput($code, [ref]$null, [ref]$null).EndBlock.Statements.FindAll([Func[Management.Automation.Language.Ast,bool]]{$args[0] -is [Management.Automation.Language.FunctionDefinitionAst]}, $false) `
                | Select-Object -ExpandProperty Name
            
            # since there might be multiple functions in the script, we want to filter and only get the validation function
            $function = $functionName | Where-Object {$_ -like "Test-*"} | Select-Object -First 1
            
            # execute the function
            if($null -ne $function){
                Invoke-Expression -Command $function
            }
        }
    }
    catch{
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    } 
}

function Test-SdnJumboPackets {
    <#
    .SYNOPSIS
        Performs Test-LogicalNetworkSupportsJumboPacket between the PA hosts
    .PARAMETER NcURI
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER ComputerName
        The computer name of the hypervisor host
    .EXAMPLE
        PS> Test-SdnJumboPackets -NcUri "https://nc.$env:USERDNSDOMANI"
    .EXAMPLE
        PS> Test-SdnJumboPackets -ComputerName 'node01','node02'
    .EXAMPLE
        PS> Test-SdnJumboPackets -ComputerName (Get-SdnServers -NcUri $NcUri -ServerNamesOnly)
    #>

    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true)]
        [uri]$NcUri,

        [parameter(Mandatory = $false)]
        [string[]]$ComputerName
    )

    try {
        "Importing HNVDiagnostics" | Trace-Output
        Import-Module HNVDiagnostics -ErrorAction Stop

        if($PSBoundParameters.ContainsKey('ComputerName')){
            if($ComputerName.Count -le 1){
                throw New-Object System.ArgumentException("A minimum of two provider hosts are required to be specified")
            }

            "Getting provider addresses from {0}" -f ($ComputerName -join ', ') | Trace-Output
            $providerAddresses = Get-SdnProviderAddresses -ComputerName $Computername
        }
        else {
            "Getting provider addresses from {0}" -f $NcUri | Trace-Output
            $providerAddresses = Get-SdnProviderAddresses -ComputerName (Get-SdnServers -NcUri $NcUri -ServerNamesOnly) 
        }

        if(!$providerAddresses){
            "No provider addresses were returned. This may be an indication that no tenant workloads have been deployed to the hosts provided" | Trace-Output -Level:Warning
            return $null
        }

        # since the first host returned may not have tenant workload and only have APIPA
        # we need to identify a valid host to perform our tests from and then break out of the foreach loop
        foreach($address in $providerAddresses){
            if($address -notlike "169*"){
                "Located address {0} that will be used as source for testing" -f $address | Trace-Output -Level:Verbose
                $sourceHost = $address.PSComputerName
                break
            }
            else {
                "Skipping address {0}" -f $address | Trace-Output -Level:Verbose
            }
        }

        if(!$sourceHost){
            "Unable to locate valid provider address to perform testing from. This may be an indication that no tenant workloads have been deployed to the hosts provided" | Trace-Output -Level:Warning
            return $null
        }

        # as these commands take a while to complete per test
        # we want to leverage jobs to speed up the process as will significantly reduce time to complete
        # in environment with more than 4 nodes
        $uniquePAHosts = $providerAddresses.PSComputerName | Sort-Object -Unique
        $jobsArray = [System.Collections.ArrayList]::new()
        $resultsArray = [System.Collections.ArrayList]::new()
        
        "Invoking jobs to validate jumbo packets can traverse between {0}" -f ($uniquePAHosts -join ', ') | Trace-Output
    
        foreach($object in $uniquePAHosts){
            $null = Start-Job -Name ($Id = "$([guid]::NewGuid().Guid)") -ScriptBlock {
                Test-LogicalNetworkSupportsJumboPacket -SourceHost $using:sourceHost -DestinationHost $using:object
            }
        
            [void]$jobsArray.Add($id)
        }

        # monitor the status of the jobs and then add to arraylist
        foreach($job in $jobsArray){
            $results = Wait-PSRemoteJob -Name $job -PollingInterval 1 -PassThru
            [void]$resultsArray.Add($results)
        }

        return $resultsArray
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}