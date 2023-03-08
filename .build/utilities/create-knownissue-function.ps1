<#
    .SYNOPSIS
        Creates new function file based off template
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [System.String]$FunctionName,

    [Parameter(Mandatory = $true)]
    [ArgumentCompleter({
        $possibleValues = Get-ChildItem -Path "$PSScriptRoot\templates\knownIssue\*" -Include *.ps1 | Select-Object -ExpandProperty Name
        return $possibleValues | ForEach-Object { $_ }
    })]
    [System.String]$Template
)

$ErrorActionPreference = 'Stop'

# verify the function name matches approved verbs
$FunctionName = (Get-Culture).TextInfo.ToTitleCase("$FunctionName".tolower())
if($FunctionName -inotlike "*"){
    "Please ensure that you are prefixing your function name wtih '' when creating known issue check." | Write-Host -ForegroundColor:Yellow
    return
}

# generate the filepath where the function will be saved
$templatePath = Get-Item -Path "$PSScriptRoot\templates\knownIssue\$($Template)"
$relativePath = "src\knownIssues\{0}.ps1" -f $FunctionName
$destinationPath = Join-Path -Path "$PSScriptRoot\..\..\" -ChildPath $relativePath

$allFunctionFiles = (Get-ChildItem -Path "$PSScriptRoot\..\..\src\*" -Include *.ps1 -Recurse)
$duplicateFunction = $allFunctionFiles | Where-Object {$_.BaseName -ieq $FunctionName}
if($duplicateFunction){
    "{0} already exists under {1}. Specify a new function name to prevent dot sourcing conflicts" -f $FunctionName, $duplicateFunction.FullName | Write-Host -ForegroundColor:Yellow
    return
}

# create the function file based off template and replace the function name within the file
$newFunctionFile = Copy-Item -Path $templatePath -Destination $destinationPath -PassThru
if($newFunctionFile){
    $content = Get-Content -Path $newFunctionFile.FullName
    $newContent = $content -Replace 'VERB-NAME', $FunctionName
    $newContent | Set-Content -Path $newFunctionFile.FullName

    "Successfully created {0}" -f $newFunctionFile.FullName | Write-Host
}
else {
    "Unable to create new function file {0}" | Write-Host -ForegroundColor:Yellow
}

$ErrorActionPreference = 'Continue'


