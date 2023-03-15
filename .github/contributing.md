# Welcome to SdnDiagnostics contributing guide
When contributing to this project, ensure you:
1. Review existing functions already available and reuse where possible.
1. Return native .NET objects whenever possible.
1. Rarely should you return from a function with format-table, format-list, etc.. If they do, they should use the PowerShell verb `Show`.
1. Environments that this module run on may be in a broken or inconcistent state, so defensive coding techniques should be leveraged.
1. Use [PowerShell Approved Verbs](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands) when creating functions.
1. Provide detailed function synopsis, description, parameters and examples. The build pipeline leverages platyPS to auto-generate documentation for the exported functions and publishes to the project wiki.

# Getting started

## Understanding the framework
The SdnDiagnostics module is composed of smaller sub-modules that are generated during the build process. Functions are stored under the appropriate \modules\SdnDiag.{Name} folder directory under either private or public folders.

During the build process, the individual ps1 files are merged into a single SdnDiag.{Name}.psm1 file that exists for each sub-module folder.

## Creating core functions
When creating core functions:

1. Functions should be placed under `src\modules\[ModuleName]\[Private | Public]\Verb-FunctionName.ps1`.
    - Function name should match the file name.
    - Limit one function per file.

1. If your function should be exported and available after module import, be sure to add your function to the export list in `src\SdnDiagnostics.psd1` under `FunctionsToExport`.

# Build validation and testing
1. To generate a local build of the module, run `.\.build\build.ps1` which will generate an SdnDiagnostics module package to `~\out\build\SdnDiagnostics`.
    - Recommend to leverage elevated PowerShell or Cmd console and not use the terminal included in VSCode due to odd issues with the PSM1 generation.
1. Copy the module to `C:\Program Files\WindowsPowerShell\Modules`.
    - Remove any existing modules if they are present.
1. Import the module using `Import-Module -Name SdnDiagnostics -Force`.
1. Install the modules to the SDN nodes in the dataplane.
```powershell
$environmentDetails = Get-SdnInfrastructureInfo -NetworkController 'NC01'
Install-SdnDiagnostics -ComputerName $environmentDetails.FabricNodes
```
