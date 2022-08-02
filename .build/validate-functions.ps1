$files = Get-ChildItem -Path "$PSScriptRoot\..\src\modules\*" -Include "*.ps1" -Recurse
foreach ($file in $files) {
    $code = Get-Content -Path $file.FullName -Raw -Encoding UTF8
    if ($null -eq $code) {
        continue
    }

    $functions = [Management.Automation.Language.Parser]::ParseInput($code, [ref]$null, [ref]$null)
    $functionName = $functions.FindAll({
        param([System.Management.Automation.Language.Ast] $ast)
        $ast -is [System.Management.Automation.Language.FunctionDefinitionAst] -and ($PSVersionTable.PSVersion.Major -lt 5 -or $ast.Parent -isnot [System.Management.Automation.Language.FunctionMemberAst])
    }, $true) | Select-Object -ExpandProperty Name

    # if functions identified within the file, enumerate them to ensure we have a single function per file
    # and that the function name matches the file name for consistency with the module
    if ($functionName) {
        if ($functionName.Count -gt 1) {
            "{0} contains {1} functions. Please look to split these functions into their own individual files." -f $file.FullName, $functionName.Count | Write-Host -ForegroundColor:Yellow
            continue
        }

        if ($file.BaseName -ine $functionName) {
            "{0} does not match function name {1}" -f $file.FullName, $functionName | Write-Host -ForegroundColor:Yellow
        }
    }
}
