function Convert-FileSystemPathToUNC {
    <#
    .SYNOPSIS
        Converts a local file path to a computer specific admin UNC path, such as C:\temp\myfile.txt to \\azs-srng01\c$\temp\myfile.txt
    #>

    param(
        [System.String]$ComputerName,
        [System.String]$Path
    )
    
    $newPath = $path.Replace([System.IO.Path]::GetPathRoot($Path),[System.IO.Path]::GetPathRoot($Path).Replace(':','$'))
    return ("\\{0}\{1}" -f $ComputerName, $newPath)
}