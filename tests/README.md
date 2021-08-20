# The SdnDiagnostics Module test

The `tests` folder include all the test script use [Pester](https://github.com/pester/Pester). 

## Folder Structure 
- `RunTests.ps1` is the start script to run all tests under tests folder. 
- `wave1`... `waveAll` include all test scripts grouped into different wave. Tests will be executed in order of wave.
## To run tests in your test environment

- Generate the configuration based on `SdnDiagnosticsTestConfig-Sample.psd1`. Do not commit change to include your test environment specific settings. 
- Copy the `tests` folder to the test environment and run
  
  `.\RunTests.ps1 -ConfigurationFile SdnDiagnosticsTestConfig-Sample.psd1`

## To create new tests

- The new test script should be named as `*originalscriptname*.Tests.ps1`. For example, `Diagnostics.Tests.ps1` include the tests function for script `Diagnostics.ps1`
- The test scripts are grouped into different wave to maintain test execution order. `wave1` ... `waveAll` . If you don't expect order of test execution, the test script need to be in `waveAll` folder.
  