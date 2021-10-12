# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-Size {
    <##>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Path')]
        [System.IO.File]$Path,

        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [System.IO.File[]]$FileName
    )

    try {
        $arrayList = [Systems.Collections.ArrayList]::new()

        switch ($PSCmdlet.ParameterSetName) {
            'File' {
                $items = Get-Item -Path $FileName -Force
            }
            'Path' {
                $items = Get-ChildItem -Path $Path -Force
            }
        }

        foreach ($item in $items) {
            if ($item.PSIsContainer -eq $true) {
                $subFolderItems = Get-ChildItem $item.FullName -Recurse | Where-Object { $_.PSIsContainer -eq $false } | Measure-Object -Property Length -Sum | Select-Object Sum
                $folderSize = Format-ByteSize -Bytes $subFolderItems.sum

                [void]$arrayList.Add([PSCustomObject]@{
                    Name     = $item
                    SizeInGB = $folderSize.GB
                    SizeInMB = $folderSize.MB
                    Size     = $subFolderItems.sum
                    Type     = "Folder"
                    FullName = $item.FullName
                })

            }
            else {
                $fileSize = Format-ByteSize -Bytes $item.Length
                [void]$arrayList.Add([PSCustomObject]@{
                    Name     = $item.Name
                    SizeInGB = $fileSize.GB
                    SizeInMB = $fileSize.MB
                    Size     = $item.Length
                    Type     = "File"
                    FullName = $item.FullName
                })
            }
        }

        return ($arrayList | Sort-Object Type, Size)
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
