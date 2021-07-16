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
            $healthValidationScripts = Get-ChildItem -Path "$PSScriptRoot\..\..\..\private\health" -Recurse | Where-Object {$_.Extension -eq '.ps1'}
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