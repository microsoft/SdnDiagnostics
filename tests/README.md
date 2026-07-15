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
- Install latest Pester by `Install-Module -Name Pester -Force -SkipPublisherCheck`. More info from [Pester Update](https://pester-docs.netlify.app/docs/introduction/installation)
- The `offline\data` folder include the sample data like `SdnApiResources`. The data is loaded into `$Global:PesterOfflineTests`
- Run offline test at offline folder by `.\RunTests.ps1`
- Run a specific test file: `.\RunTests.ps1 -TestFile ".\Utilities.Tests.ps1"`
- Run tests by tag: `.\RunTests.ps1 -Tag "Unit"`

## Run online tests in your test environment

- Generate the configuration based on `SdnDiagnosticsTestConfig-Sample.psd1`. Do not commit change to include your test environment specific settings. 
- Copy the `tests` folder to the test environment and run
  
  `.\RunTests.ps1 -ConfigurationFile SdnDiagnosticsTestConfig-Sample.psd1`

## To create new tests

See [CONTRIBUTING_TESTS.md](CONTRIBUTING_TESTS.md) for detailed instructions on adding new tests, including:
- How to structure test files
- How to write mocks for different function patterns
- How to add or modify mock data
- Naming conventions for the test environment (DVLAB prefix)
  