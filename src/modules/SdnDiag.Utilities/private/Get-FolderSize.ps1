function Get-FolderSize {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Path')]
        [System.IO.FileInfo]$Path,

        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [System.IO.FileInfo[]]$FileName,

        [Parameter(Mandatory = $false, ParameterSetName = 'File')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Path')]
        [Switch]$Total
    )

    try {
        $arrayList = [System.Collections.ArrayList]::new()

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

        if ($Total) {
            $totalSize = $arrayList | Measure-Object -Property Size -Sum
            $totalSizeFormatted = Format-ByteSize -Bytes $totalSize.Sum

            return $totalSizeFormatted
        }

        return ($arrayList | Sort-Object Type, Size)
    }
    catch {
       $_ | Trace-Output -Level:Error
    }
}
