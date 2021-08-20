# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-OvsdbDatabase {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [OvsdbTable]$Table
    )

    try {
        $localPort = Get-NetTCPConnection -LocalPort:6641 -ErrorAction:SilentlyContinue
        if(!$localPort){
            throw New-Object System.NullReferenceException("No endpoint listening on port 6641. Ensure NCHostAgent service is running.")
        }

        $cmdline = "ovsdb-client.exe dump tcp:127.0.0.1:6641 -f json {0}" -f $Table
        $databaseResults = Invoke-Expression $cmdline | ConvertFrom-Json

        if(!$databaseResults){
            $msg = "Unable to retrieve OVSDB results`n`t{0}" -f $_
            throw New-Object System.NullReferenceException($msg)
        }
        else {
            return $databaseResults
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
