# The SdnDiagnostics Module test

The `tests` folder include all the test script use [Pester](https://github.com/pester/Pester). 

## Offline Tests

All tests are **offline** — they run without a real SDN deployment by mocking external calls with sample data.

## Folder Structure 
- `offline\RunTests.ps1` is the start script to run all offline tests under the offline test folder. 
- `offline\data\` contains mock JSON data loaded into `$Global:PesterOfflineTests`

## Run offline tests
- Install latest Pester by `Install-Module -Name Pester -Force -SkipPublisherCheck`. More info from [Pester Update](https://pester-docs.netlify.app/docs/introduction/installation)
- Build the module first: run `.\build.ps1` from the repo root to populate `out/build/`
- The `offline\data` folder include the sample data like `SdnApiResources`. The data is loaded into `$Global:PesterOfflineTests`
- Run offline test at offline folder by `.\RunTests.ps1`
- Run a specific test file: `.\RunTests.ps1 -TestFile ".\Utilities.Tests.ps1"`

## To create new tests

See [CONTRIBUTING_TESTS.md](CONTRIBUTING_TESTS.md) for detailed instructions on adding new tests, including:
- How to structure test files
- How to write mocks for different function patterns
- How to add or modify mock data
- Naming conventions for the test environment (DVLAB prefix)
  