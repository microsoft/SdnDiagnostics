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
2. If your function should be exported and available after module import, be sure to add your function to the export list in `~/SDNDiagnostics.psd1`.
3. Return native .NET objects whenever possible.
4. Rarely should you return from a function with format-table, format-list, etc..
5. Environments that this module run on may be in a broken or inconcistent state, so defensive coding techniques should be leveraged.
6. Leverage `$Global:SdnDiagnostics` for caching when appropriate. 


## Creating Health Validation Tests
When creating a health validation test, ensure you:
1. Create the `ps1` file under `~/src/modules/private/health` as the name of the validation test. e.g. `Test-ServerHealth.ps1`
2. Function should return a PSCustomObject that contains the following format:
    ```
    if($unhealthyNode){
        return [PSCustomObject]@{
            Status = 'Failure'
            Properties = $arrayList
        }
    }
    else {
        return [PSCustomObject]@{
            Status = 'Success'
            Properties = $arrayList
        }
    }
    ```
3. Health validation tests are executed using `Debug-SdnFabricInfrastructure`. This function will automatically pick up tests under the `~/src/modules/private/health` directory.
## Creating Known Issue Tests
1. Create the `ps1` file under `~/src/modules/private/knownIssues` as the name of the validation test. e.g. `Test-VfpDuplicatePort.ps1`
2. Function should return a PSCustomObject that contains the following format:
    ```
    if($issueFound)
        return [PSCustomObject]@{
            Result = $true
            Properties = $duplicateObjects
        }
    }
    else {
        return [PSCustomObject]@{
            Result = $false
            Properties = $null
        }
    }
    ```
3. Known Issue tests are executed using `Test-SdnKnownIssues`. This function will automatically pick up tests under the `~/src/modules/private/knownIssues` directory.
# Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
