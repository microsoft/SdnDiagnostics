# The SdnDiagnostics Module test

The `tests` folder include all the test script use [Pester](https://github.com/pester/Pester). 

## Offline and Online Tests

The tests are categorized into two type of tests **offline** and **online**

- **offline** test can be run without real SDN deployment through mock based on sample data collected from SDN deployment. 
- **online** test need to run against SDN deployment

## Folder Structure 
- `offline\RunTests.ps1` is the start script to run all offline tests under offline test folder. 
- `online\RunTests.ps1` is the start script to run all online tests under online folder. 
- `wave1`... `waveAll` include all test scripts grouped into different wave. Tests will be executed in order of wave.

## Run offline tests
- The `offline\data` folder include the sample data like `SdnApiResources`. The data is loaded into `$Global:PesterOfflineTest`
- Run offline test at offline folder by `.\RunTests.ps1`

## Run online tests in your test environment

- Generate the configuration based on `SdnDiagnosticsTestConfig-Sample.psd1`. Do not commit change to include your test environment specific settings. 
- Copy the `tests` folder to the test environment and run
  
  `.\RunTests.ps1 -ConfigurationFile SdnDiagnosticsTestConfig-Sample.psd1`

## To create new tests

- If your test function can be mocked with sample data, put it under `offline` folder. Otherwise, this have to be under `online` folder.
- For offline test, sample data can be consumed from `$Global:PesterOfflineTest` to write your mock.
- The new test script should be named as `*originalscriptname*.Tests.ps1`. For example, `Diagnostics.Tests.ps1` include the tests function for script `Diagnostics.ps1`
- The online test scripts are grouped into different wave to maintain test execution order. `wave1` ... `waveAll` . If you don't expect order of test execution, the test script need to be in `waveAll` folder.
  