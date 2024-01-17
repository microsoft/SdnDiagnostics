function Export-ObjectToFile {
    <#
    .SYNOPSIS
        Save an object to a file in a consistent format.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [Object[]]$Object,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$FilePath,

        [Parameter(Mandatory = $false)]
        [System.String]$Prefix,

        [Parameter(Mandatory = $true)]
        [System.String]$Name,

        [Parameter(Mandatory = $false)]
        [ValidateSet("json","csv","txt")]
        [System.String]$FileType = "json",

        [Parameter(Mandatory = $false)]
        [ValidateSet("Table","List")]
        [System.String]$Format,

        [Parameter(Mandatory = $false)]
        [System.String]$Depth = 2
    )

    begin {
        $arrayList = [System.Collections.ArrayList]::new()

        # if object is null, then exit
        if ($null -eq $Object) {
            return
        }
    }
    process {
        foreach ($obj in $Object) {
            [void]$arrayList.add($obj)
        }
    }
    end {
        try {
            # build the file directory and name that will be used to export the object out
            if($Prefix){
                [System.String]$formattedFileName = "{0}\{1}_{2}.{3}" -f $FilePath.FullName, $Prefix, $Name, $FileType
            }
            else {
                [System.String]$formattedFileName = "{0}\{1}.{2}" -f $FilePath.FullName, $Name, $FileType
            }

            [System.IO.FileInfo]$fileName = $formattedFileName

            # create the parent directory structure if does not already exist
            if(!(Test-Path -Path $fileName.Directory -PathType Container)){
                "Creating directory {0}" -f $fileName.Directory | Trace-Output -Level:Verbose
                $null = New-Item -Path $fileName.Directory -ItemType Directory
            }

            "Creating file {0}" -f $fileName | Trace-Output -Level:Verbose
            switch($FileType){
                "json" {
                    $arrayList | ConvertTo-Json -Depth $Depth | Out-File -FilePath $fileName -Force
                }
                "csv" {
                    $arrayList | Export-Csv -NoTypeInformation -Path $fileName -Force
                }
                "txt" {
                    $FormatEnumerationLimit = 500
                    switch($Format){
                        'Table' {
                            $arrayList | Format-Table -AutoSize -Wrap | Out-String -Width 4096 | Out-File -FilePath $fileName -Force
                        }
                        'List' {
                            $arrayList | Format-List -Property * | Out-File -FilePath $fileName -Force
                        }
                        default {
                            $arrayList | Out-File -FilePath $fileName -Force
                        }
                    }
                }
            }
        }
        catch {
            $_ | Trace-Exception
        }
    }
}
