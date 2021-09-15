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
        $possibleValues = Get-ChildItem -Path "$PSScriptRoot\..\..\src\modules" -Directory | Select-Object -ExpandProperty Name
        return $possibleValues | ForEach-Object { $_ }
    })]
    [System.String]$Module,

    [Parameter(Mandatory = $true)]
    [ArgumentCompleter({
        $possibleValues = Get-ChildItem -Path "$PSScriptRoot\templates\module\*" -Include *.ps1 | Select-Object -ExpandProperty Name
        return $possibleValues | ForEach-Object { $_ }
    })]
    [System.String]$Template,

    [Parameter(Mandatory = $false)]
    [Switch]$IsPublic
)

$ErrorActionPreference = 'Stop'

# verify the function name matches approved verbs
$FunctionName = (Get-Culture).TextInfo.ToTitleCase("$FunctionName".tolower())
$verb = $FunctionName.Split('-')[0]
if($verb -inotin (Get-Verb).Verb){
    $publicDocURL = 'https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands'
    "{0} is not using an Approved Verb. Run 'Get-Verb' for a list of allowed verbs or see {1} for more details." -f $FunctionName, $publicDocURL | Write-Host -ForegroundColor:Yellow
    return
}

# generate the filepath where the function will be saved
if($IsPublic){
    $subPath = 'public'
}
else {
    $subPath = 'private'
}

$templatePath = Get-Item -Path "$PSScriptRoot\templates\module\$($Template)"
$relativePath = "src\modules\{0}\{1}\{2}.ps1" -f $Module, $subPath, $FunctionName
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


