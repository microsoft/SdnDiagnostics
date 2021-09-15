# Project
SdnDiagnostics is a PowerShell module that is designed to simplify the diagnostic troubleshooting and data collection process when troubleshooting issues related to [Microsoft Software Defined Network](https://docs.microsoft.com/en-us/windows-server/networking/sdn/software-defined-networking).
# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

When contributing to this project, ensure you:
1. Review existing functions already available and reuse where possible.
1. Functions should be placed under `src\modules\[ModuleName]\[Private | Public]\Verb-FunctionName.ps1`. 
    - Function name should match the file name.
    - Limit one function per file.
    - Ensure that the file name is added to `src\SDNDiagnostics.psm1` so it is dot sourced on module import.
    - Use [Approved Verbs for PowerShell Commands](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands).
1. If your function should be exported and available after module import, be sure to add your function to the export list in `src\SDNDiagnostics.psd1` under `FunctionsToExport`.
1. Return native .NET objects whenever possible.
1. Rarely should you return from a function with format-table, format-list, etc.. If they do, they should use the PowerShell verb `Show`.
1. Environments that this module run on may be in a broken or inconcistent state, so defensive coding techniques should be leveraged.
1. Leverage `$Global:SdnDiagnostics` for caching when appropriate. 


## Creating Health Validation Tests
When creating a health validation test, ensure you:
1. Create the `ps1` file under `src\health\[role]\` as the name of the validation test. e.g. `Test-SdnServerHealth.ps1`
1. Function should return a PSCustomObject that contains the following format:
    ```
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

## Creating Known Issue Tests
1. Create the `ps1` file under `src\knownIssues` as the name of the validation test. e.g. `Test-SdnKIVfpDuplicatePort.ps1`
1. Function should return a PSCustomObject that contains the following format:
    ```
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

# Build Validation and Testing
1. To generate a local build of the module, run `.\.build\build.ps1` which will generate an SdnDiagnostics module package to `~\out\build\SdnDiagnostics`. 
1. Copy the module to `C:\Program Files\WindowsPowerShell\Modules`.
1. Import the module using `Import-Module -Name SdnDiagnostics -Force`.
1. Install the modules to the SDN nodes in the dataplane. 
```powershell
$uri = 'https://NcURI'
$netConroller = 'NC01' 

$nodes = @()
$nodes += (Get-SdnServer -NcUri $uri -ManagementAddress)
$nodes += (Get-SdnGateway -NcUri $uri -ManagementAddress)
$nodes += (Get-SdnLoadBalancerMux -NcUri $uri -ManagementAddress)
$nodes += (Get-SdnNetworkController -NetworkController $netController -ServerNameOnly)

Install-SdnDiagnostic -ComputerName $nodes -Force
```
# Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
