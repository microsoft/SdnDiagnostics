# Welcome to SdnDiagnostics contributing guide
When contributing to this project, ensure you:
1. Review existing functions already available and reuse where possible.
1. Return native .NET objects whenever possible.
1. Rarely should you return from a function with format-table, format-list, etc.. If they do, they should use the PowerShell verb `Show`.
1. Environments that this module run on may be in a broken or inconcistent state, so defensive coding techniques should be leveraged.
1. Leverage `$Global:SdnDiagnostics` for caching when appropriate.
1. Use [PowerShell Approved Verbs](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands) when creating functions.
1. Provide detailed function synopsis, description, parameters and examples. The build pipeline leverages platyPS to auto-generate documentation for the exported functions and publishes to the project wiki.

# Getting started


## Creating core functions
When creating core functions:

1. Functions should be placed under `src\modules\[ModuleName]\[Private | Public]\Verb-FunctionName.ps1`.
    - Function name should match the file name.
    - Limit one function per file.

1. If your function should be exported and available after module import, be sure to add your function to the export list in `src\SdnDiagnostics.psd1` under `FunctionsToExport`.

To help ensure consistency, leverage `.build\utilities\create-function.ps1` to help create your functions. This will create a `.ps1` file off the specified template and place into the appropriate module directory. Example:
```powershell
.\create-core-function.ps1 -FunctionName 'Disable-SdnRasGatewayTracing' -Module Gateway -Template basic_template.ps1 -IsPublic
```
- You only need to specify the `FunctionName` property. The other properties leverage ArgumentCompleters and will allow you to tab complete to pick a choice. Specify `-IsPublic` if you are planning for this function to be exported.

# Creating health validation tests
When creating a health validation test, ensure you:
1. Create the `ps1` file under `src\health\[role]\` as the name of the validation test. e.g. `Test-SdnServerHealth.ps1`
1. Function should return a PSCustomObject that contains the following format:
    ```powershell
    # $status should contain either 'Success' or 'Failure'
    # $properties will contain any related information in scenario of 'Failure' status
    else {
        return [PSCustomObject]@{
            Status = $status
            Properties = $arrayList
        }
    }
    ```
1. Health validation tests are executed using `Debug-SdnFabricInfrastructure` or executing the cmdlet directly.
    - `Debug-SdnFabricInfrastructure` will automatically pick up tests under the `src\health` directory.
1. The infrastructure information can be retrieved from global cache at `$Global:SdnDiagnostics`

To help ensure consistency, leverage `.build\utilities\create-health-function.ps1` to help create your functions. This will create a `.ps1` file off the specified template and place into the appropriate module under `src\health`. Example:
```powershell
.\create-health-function.ps1 -FunctionName 'Test-SdnLoadBalancerMuxOnline' -Module LoadBalancerMux -Template basic_health_template.ps1
```
- You only need to specify the `FunctionName` property. The other properties leverage ArgumentCompleters and will allow you to tab complete to pick a choice.

# Creating known issue tests
1. Create the `ps1` file under `src\knownIssues` as the name of the validation test. e.g. `Test-SdnKIVfpDuplicatePort.ps1`
    - Ensure that you prefix your function name as `Test-SdnKI`.
1. Function should return a PSCustomObject that contains the following format:
    ```powershell
    # $issueIdentified should either be $true or $false depending on if issue was detected
    # $properties will contain any related information in scenario of $true status
    else {
        return [PSCustomObject]@{
            Result = $issueIdentified
            Properties = $arrayList
        }
    }
    ```
1. Known Issue tests are executed using `Test-SdnKnownIssues` or executing the cmdlet directly.
    - `Test-SdnKnownIssues` will automatically pick up tests under the `src\knownIssues` directory.
1. The infrastructure information can be retrieved from global cache at `$Global:SdnDiagnostics`

To help ensure consistency, leverage `.build\utilities\create-knownissue-function.ps1` to help create your functions. This will create a `.ps1` file off the specified template and place into the appropriate module under `src\knownIssues`. Example:
```powershell
.\create-knownissue-function.ps1 -FunctionName 'Test-SdnKIVfpDuplicatePort' -Template basic_knownIssue_template.ps1
```
- You only need to specify the `FunctionName` property. The other properties leverage ArgumentCompleters and will allow you to tab complete to pick a choice.

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
