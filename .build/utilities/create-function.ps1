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
        $possibleValues = Get-ChildItem -Path "$PSScriptRoot\templates\*" -Include *.ps1 | Select-Object -ExpandProperty Name
        return $possibleValues | ForEach-Object { $_ }
    })]
    [System.String]$Template,

    [Parameter(Mandatory = $false)]
    [Switch]$IsPublic
)

$ErrorActionPreference = 'Stop'

# verify the function name matches approved verbs
$verb = $FunctionName.Split('-')[0]
if($verb -inotin (Get-Verb).Verb){
    $publicDocURL = 'https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands'
    "{0} is not using an Approved Verb. Run 'Get-Verb' for a list of allowed verbs or see {1} for more details." -f $FunctionName, $publicDocURL | Write-Host -ForegroundColor:Yellow
    return
}

# retrieve the template that will be used
$templatePath = Get-Item -Path "$PSScriptRoot\templates\$($Template)"

# generate the filepath where the function will be saved
if($IsPublic){
    $subPath = 'public'
}
else {
    $subPath = 'private'
}

$relativePath = ("src\modules\$($Module)\$($subPath)\$($FunctionName).ps1")
$destinationPath = Join-Path -Path "$PSScriptRoot\..\..\" -ChildPath $relativePath

$allFunctionFiles = (Get-ChildItem -Path "$PSScriptRoot\..\..\src\modules\*" -Include *.ps1 -Recurse)
$duplicateFunction = $allFunctionFiles | Where-Object {$_.BaseName -ieq $FunctionName}
if($duplicateFunction){
    "{0} already exists under {1}. Specify a new function name to prevent dot sourcing conflicts" -f $FunctionName, $duplicateFunction.FullName | Write-Host -ForegroundColor:Yellow
    return
}

# create the function file based off template and replace the function name within the file
$newFunctionFile = Copy-Item -Path $templatePath -Destination $destinationPath -PassThru
if($newFunctionFile){
    "Successfully created {0}" -f $newFunctionFile.FullName | Write-Host
    $content = Get-Content -Path $newFunctionFile.FullName
    $newContent = $content -Replace 'VERB-NAME', $FunctionName
    $newContent | Set-Content -Path $newFunctionFile.FullName
}
else {
    "Unable to create new function file {0}" | Write-Host -ForegroundColor:Yellow
}

$ErrorActionPreference = 'Continue'


