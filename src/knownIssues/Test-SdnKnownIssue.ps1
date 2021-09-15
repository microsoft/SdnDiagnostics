# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-SdnKnownIssue {
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
                $possibleValues = Get-ChildItem -Path $PSScriptRoot -Recurse | Where-Object { $_.Extension -eq '.ps1' -and $_.BaseName -ilike "Test-SdnKI*" } | Select-Object -ExpandProperty BaseName
                return $possibleValues | ForEach-Object { $_ }
            })]
        [System.String]$Test
    )

    try {
        $arrayList = [System.Collections.ArrayList]::new()

        if ($PSBoundParameters.ContainsKey('Credential')) {
            $Global:SdnDiagnostics.Credential = $Credential
        }

        if ($PSBoundParameters.ContainsKey('NcRestCredential')) {
            $Global:SdnDiagnostics.NcRestCredential = $NcRestCredential
        }
       
        $environmentInfo = Get-SdnInfrastructureInfo -NetworkController $NetworkController -Credential $Credential -NcRestCredential $NcRestCredential
        if ($null -eq $environmentInfo) {
            throw New-Object System.NullReferenceException("Unable to retrieve environment details")
        }

        if ($PSBoundParameters.ContainsKey('Test')) {
            $knownIssueScripts = Get-ChildItem -Path $PSScriptRoot -Recurse | Where-Object { $_.BaseName -ieq $Test }
        }
        else {
            $knownIssueScripts = Get-ChildItem -Path $PSScriptRoot -Recurse | Where-Object { $_.Extension -eq '.ps1' -and $_.BaseName -ilike "Test-SdnKI*" }
        }

        if ($null -eq $knownIssueScripts) {
            throw New-Object System.NullReferenceException("No known issue scripts found")
        }

        "Located {0} known issue scripts" -f $healthValidationScripts.Count | Trace-Output -Level:Verbose 
        foreach ($script in $knownIssueScripts) {
            $functions = Get-FunctionFromFile -FilePath $script.FullName -Verb 'Test'
            if ($functions) {
                foreach ($function in $functions) {
                    "Executing {0}" -f $function | Trace-Output -Level:Verbose
                    $result = Invoke-Expression -Command $function

                    $object = [PSCustomObject]@{
                        Name       = $function
                        Result     = $result.Result
                        Properties = $result.Properties
                    }

                    [void]$arrayList.Add($object)
                }
            }
        }

        $Global:SdnDiagnostics.Credential = $null
        $Global:SdnDiagnostics.NcRestCredential = $null
        $Global:SdnDiagnostics.Cache.KnownIssues = $arrayList

        "Results for known issues have been saved to {0} for further analysis" -f '$Global:SdnDiagnostics.Cache.KnownIssues' | Trace-Output
        return $Global:SdnDiagnostics.Cache.KnownIssues
    }
    catch {
        $Global:SdnDiagnostics.Credential = $null
        $Global:SdnDiagnostics.NcRestCredential = $null
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    } 
}