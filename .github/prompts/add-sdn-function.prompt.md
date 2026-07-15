---
description: Add a new function to SdnDiagnostics with corresponding Pester tests
mode: agent
tools:
  - view
  - edit
  - create
  - grep
  - glob
  - powershell
---

# Add SDN Function

Create a new function in the SdnDiagnostics module and generate its corresponding offline Pester tests.

## Phase 1: Create the Function

### Determine the target module

Place the function in the correct module based on its role:

| Module | Purpose | Location |
|--------|---------|----------|
| `SdnDiag.Utilities` | Pure helpers (Format-*, Confirm-*, Convert-*) | `src/modules/SdnDiag.Utilities/` |
| `SdnDiag.Common` | Shared SDN operations | `src/modules/SdnDiag.Common/` |
| `SdnDiag.NetworkController` | NC REST API operations | `src/modules/SdnDiag.NetworkController/` |
| `SdnDiag.Server` | Hyper-V host operations | `src/modules/SdnDiag.Server/` |
| `SdnDiag.Gateway` | Gateway operations | `src/modules/SdnDiag.Gateway/` |
| `SdnDiag.LoadBalancerMux` | Mux operations | `src/modules/SdnDiag.LoadBalancerMux/` |
| `SdnDiag.Health` | Health validation logic | `src/modules/SdnDiag.Health/` |

### Function structure requirements

```powershell
function Verb-SdnNoun {
    <#
    .SYNOPSIS
        Brief description.
    .DESCRIPTION
        Detailed description.
    .PARAMETER ParameterName
        Parameter description.
    .EXAMPLE
        PS> Verb-SdnNoun -Parameter "value"
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RequiredParam,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        # Function logic
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
```

### For NC REST functions, include parameter sets

```powershell
[CmdletBinding(DefaultParameterSetName = 'RestCredential')]
param(
    [Parameter(Mandatory = $true)]
    [uri]$NcUri,

    [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
    [X509Certificate]$NcRestCertificate,

    [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
)
```

### Conventions

- Use approved PowerShell verbs (Get-, Set-, New-, Remove-, Test-, Confirm-, Format-)
- PascalCase for function/parameter names, camelCase for local variables
- Use `Trace-Output` for logging (not Write-Host/Write-Verbose)
- Use `Invoke-PSRemoteCommand` for remote execution
- Use `Get-SdnResource` for NC REST API calls

## Phase 2: Create Pester Tests

After creating the function, generate its offline Pester tests.

### Determine the mock pattern

1. **Read the function source** — identify what external calls it makes
2. **Select pattern:**
   - **Pattern A (pure unit):** No external calls — test inputs/outputs directly. Wrap in `InModuleScope SdnDiagnostics { ... }` for private/internal functions.
   - **Pattern B (NC REST):** Calls `Invoke-RestMethodWithRetry` internally — mock it inside `InModuleScope SdnDiag.NetworkController`
   - **Pattern C (remote command):** Calls `Invoke-PSRemoteCommand` — mock it inside `InModuleScope <NestedModuleName>`

### Create or update the test file

Test file: `tests/offline/<ModuleName>.Tests.ps1` (e.g., `NetworkController.Tests.ps1`)

#### Pattern A — Pure unit test (private functions)

```powershell
Describe 'Utilities - Format-MyFunction' {
    It "Returns expected output for valid input" {
        InModuleScope SdnDiagnostics {
            $result = Format-MyFunction -Input "test"
            $result | Should -Be "expected"
        }
    }

    It "Handles edge case" {
        InModuleScope SdnDiagnostics {
            { Format-MyFunction -Input $null } | Should -Throw
        }
    }
}
```

#### Pattern B — NC REST mock

```powershell
Describe 'NetworkController - Get-SdnMyResource' {
    It "Returns resources" {
        InModuleScope SdnDiag.NetworkController {
            Mock Invoke-RestMethodWithRetry {
                $path = ([Uri]$Uri).AbsolutePath
                if ($path -match '/networking/v1/(.+)$') {
                    $resourceType = ($Matches[1] -split '/')[0]
                    $refKey = "/$($Matches[1])"
                    if ($Global:PesterOfflineTests.SdnApiResourcesByRef.ContainsKey($refKey)) {
                        return $Global:PesterOfflineTests.SdnApiResourcesByRef[$refKey]
                    }
                    return [PSCustomObject]@{ value = $Global:PesterOfflineTests.SdnApiResources[$resourceType] }
                }
            }
            $result = Get-SdnMyResource -NcUri "https://dvlab-nc.dvlab.contoso.local"
            $result | Should -Not -BeNullOrEmpty
        }
    }
}
```

#### Pattern C — Remote command mock

```powershell
Describe 'Server - Get-SdnMyRemoteData' {
    It "Returns remote data" {
        InModuleScope SdnDiag.Server {
            Mock Invoke-PSRemoteCommand {
                return @{ Status = "OK"; Data = "mocked" }
            }
            $result = Get-SdnMyRemoteData -ComputerName "DVLAB-S1-N01"
            $result.Status | Should -Be "OK"
        }
    }
}
```

### Mock data conventions

- Prefix: `DVLAB`, Domain: `dvlab.contoso.local`
- NC URI: `https://dvlab-nc.dvlab.contoso.local`
- Servers: `DVLAB-S1-N01` through `DVLAB-S1-N04` (N04 is intentionally Failed)
- NCs: `DVLAB-NC01` through `DVLAB-NC03`
- Gateways: `DVLAB-GW01` through `DVLAB-GW03`
- Muxes: `DVLAB-MUX01`, `DVLAB-MUX02`

If new mock data is needed, add to `tests/offline/data/SdnApiResources/` using `{ "value": [...], "nextLink": "" }` wrapper format.

### Test rules

- Pester v5+ syntax only (`Should -Be`, not `Should Be`)
- One assertion per `It` block
- Test both success and failure paths
- Use `InModuleScope SdnDiagnostics { ... }` for private/internal utility functions
- Use `InModuleScope SdnDiag.NetworkController { ... }` for NC REST mocks (mock + call together)
- Always use `-NcUri` as a named parameter (it is NOT positional)
- Descriptive names: describe WHAT is validated
- Independent `Describe` blocks — no cross-block dependencies

## Checklist

After both phases complete, verify:

- [ ] Function uses approved verb and follows `Verb-SdnNoun` naming
- [ ] Function includes comment-based help (Synopsis, Description, Parameters, Example)
- [ ] Function includes try/catch with `Trace-Exception` and `Write-Error`
- [ ] Test file exists in `tests/offline/` with at least 2 test cases (happy path + edge case)
- [ ] Mock data references match existing files in `tests/offline/data/SdnApiResources/`
- [ ] Any new mock data uses DVLAB naming and the `{value:[]}` wrapper format
