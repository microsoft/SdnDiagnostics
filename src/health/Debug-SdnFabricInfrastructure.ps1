# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Debug-SdnFabricInfrastructure {
    <#
    .SYNOPSIS
        Executes a series of fabric validation tests to validate the state and health of the underlying components within the SDN fabric.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operates.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
	.PARAMETER NcRestCredential
		Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    .EXAMPLE
        PS> Debug-SdnFabricInfrastructure
    .EXAMPLE
        PS> Debug-SdnFabricInfrastructure -NetworkController 'NC01' -Credential (Get-Credential) -NcRestCredential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$NetworkController,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [ArgumentCompleter({
            $possibleValues = Get-ChildItem -Path $PSScriptRoot -Directory | Select-Object -ExpandProperty Name
            return $possibleValues | ForEach-Object { $_ }
        })]
        [System.String]$Role
    )

    try {
        $arrayList = [System.Collections.ArrayList]::new()

        if($PSBoundParameters.ContainsKey('Credential')){
            $Global:SdnDiagnostics.Credential = $Credential
        }

        if($PSBoundParameters.ContainsKey('NcRestCredential')){
            $Global:SdnDiagnostics.NcRestCredential = $NcRestCredential
        }

        $environmentInfo = Get-SdnInfrastructureInfo -NetworkController $NetworkController -Credential $Credential -NcRestCredential $NcRestCredential
        if($null -eq $environmentInfo){
            throw New-Object System.NullReferenceException("Unable to retrieve environment details")
        }

        if($PSBoundParameters.ContainsKey('Role')){
            $healthValidationScripts = Get-ChildItem -Path "$PSScriptRoot\$Role" -Recurse | Where-Object {$_.Extension -eq '.ps1' -and $_.BaseName -ilike "Test-*"}
        }
        else {
            $healthValidationScripts = Get-ChildItem -Path $PSScriptRoot -Recurse | Where-Object {$_.Extension -eq '.ps1' -and $_.BaseName -ilike "Test-*"}
        }

        if($null -eq $healthValidationScripts){
            throw New-Object System.NullReferenceException("No health validations returned")
        }

        "Located {0} health validation scripts" -f $healthValidationScripts.Count | Trace-Output -Level:Verbose
        foreach($script in $healthValidationScripts){
            $functions = Get-FunctionFromFile -FilePath $script.FullName -Verb 'Test'
            if($functions){
                foreach($function in $functions){
                    "Executing {0}" -f $function | Trace-Output -Level:Verbose
                    $result = Invoke-Expression -Command $function

                    $object = [PSCustomObject]@{
                        Name = $function
                        Status = $result.Status
                        Properties = $result.Properties
                    }

                    [void]$arrayList.Add($object)
                }
            }
        }

        $Global:SdnDiagnostics.Credential = $null
        $Global:SdnDiagnostics.NcRestCredential = $null
        $Global:SdnDiagnostics.Cache.FabricHealth = $arrayList

        "Results for fabric health have been saved to {0} for further analysis. Use Get-SdnFabricInfrastructureHealth to examine the results." -f '$Global:SdnDiagnostics.Cache.FabricHealth' | Trace-Output
        return $Global:SdnDiagnostics.Cache.FabricHealth
    }
    catch {
        $Global:SdnDiagnostics.Credential = $null
        $Global:SdnDiagnostics.NcRestCredential = $null
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
