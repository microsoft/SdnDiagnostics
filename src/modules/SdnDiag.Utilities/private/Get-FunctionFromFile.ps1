function Get-FunctionFromFile {
    <#
    .SYNOPSIS
        Enumerates a ps1 file to identify the functions defined within
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$FilePath,

        [Parameter(Mandatory = $true)]
        [System.String]$Verb
    )

    try {
        # get the raw content of the script
        $code = Get-Content -Path $FilePath.FullName -Raw

        # list all the functions in ps1 using language namespace parser
        $functionName = [Management.Automation.Language.Parser]::ParseInput($code, [ref]$null, [ref]$null).EndBlock.Statements.FindAll([Func[Management.Automation.Language.Ast,bool]]{$args[0] -is [Management.Automation.Language.FunctionDefinitionAst]}, $false) `
            | Select-Object -ExpandProperty Name

        if($functionName){
            return ($functionName | Where-Object {$_ -like "$Verb-*"})
        }
        else {
            return $null
        }
    }
    catch {
       $_ | Trace-Output -Level:Error
    }
}
