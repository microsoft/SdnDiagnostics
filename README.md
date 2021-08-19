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
1. Create the `ps1` file under `src\health\<role>\` as the name of the validation test. e.g. `Test-SdnServerHealth.ps1`
    - Filename and function name should match.
    - Ensure that the file is added to `SdnDiagnostics.psm1` under the `$healthValidations` so it can be dot sourced.
    - Ensure the function is exported by adding it to `SdnDiagnostics.psd1` under `FunctionsToExport`
2. Function should return a PSCustomObject that contains the following format:
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
3. Health validation tests are executed using `Debug-SdnFabricInfrastructure` or executing the cmdlet directly.
 - `Debug-SdnFabricInfrastructure` will automatically pick up tests under the `\src\health` directory.
4. The infrastructure information can be retrieved from global cache at `$Global:SdnDiagnostics`

## Creating Known Issue Tests
1. Create the `ps1` file under `src\knownIssues` as the name of the validation test. e.g. `Test-SdnKIVfpDuplicatePort.ps1`
    - Filename and function name should match and should be prefixed with `Test-SdnKI*`.
    - Ensure that the file is added to `SdnDiagnostics.psm1` under the `$knownIssues` so it can be dot sourced.
    - Ensure the function is exported by adding it to `SdnDiagnostics.psd1` under `FunctionsToExport`
2. Function should return a PSCustomObject that contains the following format:
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
3. Known Issue tests are executed using `Test-SdnKnownIssues` or executing the cmdlet directly.
 - `Test-SdnKnownIssues` will automatically pick up tests under the `src\health` directory.
4. The infrastructure information can be retrieved from global cache at `$Global:SdnDiagnostics`
# Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
