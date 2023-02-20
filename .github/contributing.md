# Welcome to SdnDiagnostics contributing guide
When contributing to this project, ensure you:
1. Review existing functions already available and reuse where possible.
1. Return native .NET objects whenever possible.
1. Rarely should you return from a function with format-table, format-list, etc.. If they do, they should use the PowerShell verb `Show`.
1. Environments that this module run on may be in a broken or inconcistent state, so defensive coding techniques should be leveraged.
1. Leverage `$Global:SdnDiagnostics` for caching when appropriate.
1. Use [PowerShell Approved Verbs](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands) when creating functions.
1. Provide detailed function synopsis, description, parameters and examples. The build pipeline leverages platyPS to auto-generate documentation for the exported functions and publishes to the project wiki.


# Build validation and testing
1. To generate a local build of the module, run `.\build.ps1` which will generate an SdnDiagnostics module package to `out\build\SdnDiagnostics`.
    - External packages are not automatically included in the `out\build\SdnDiagnostics` directory, however are included in the `out\package\SdnDiagnostics.*.nupkg`
    - Recommend to leverage elevated PowerShell or Cmd console and not use the terminal included in VSCode due to odd issues with the PSM1 generation.
1. Copy the module to `C:\Program Files\WindowsPowerShell\Modules`.
    - Remove any existing modules if they are present.
1. Import the module using `Import-Module -Name SdnDiagnostics -Force`.
1. Install the modules to the SDN nodes in the dataplane.
```powershell
$environmentDetails = Get-SdnInfrastructureInfo -NetworkController 'NC01'
Install-SdnDiagnostics -ComputerName $environmentDetails.FabricNodes
```
