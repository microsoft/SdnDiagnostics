# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function VERB-NAME {
    <#
    .SYNOPSIS
        <simple overview>
    .DESCRIPTION
        <detailed overview>
    .PARAMETER PARAM
        <parameter description>
    .EXAMPLE
        PS> <sample 1>
    .EXAMPLE
        PS> <sample 2>
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [TypeName]$ParameterName
    )

    try {

    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}