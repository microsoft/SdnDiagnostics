---
description: Generate offline Pester tests for a SdnDiagnostics function
mode: agent
tools:
  - view
  - edit
  - create
  - grep
  - glob
  - powershell
---

# Create Pester Tests

Generate offline Pester tests for the specified function(s) in the SdnDiagnostics module.

## Instructions

1. Read the function source to understand its parameters, internal calls, and return type.
2. Determine the correct mock pattern:
   - **Pattern A (pure unit):** Function transforms input without external calls (Format-*, Confirm-*, Convert-*)
   - **Pattern B (NC REST mock):** Function internally calls `Get-SdnResource` or NC REST API
   - **Pattern C (remote command mock):** Function uses `Invoke-PSRemoteCommand` or `Invoke-Command`
3. Create or update the appropriate test file in `tests/offline/` named after the source module.
4. Follow the mock data conventions documented in `.github/instructions/pester-tests.instructions.md`.
5. If new mock data is needed, add it to `tests/offline/data/SdnApiResources/` using DVLAB naming.

## Test Structure Requirements

- Use Pester v5+ syntax (`Should -Be`, not `Should Be`)
- One assertion per `It` block
- Include both success and failure/edge case tests
- Use `BeforeAll` for shared mocks (not `BeforeEach`)
- Use descriptive test names that say WHAT is validated
- Wrap in `Describe '<ModuleName> - <FunctionName>'`

## Mock Data Naming

- Deployment prefix: `DVLAB`
- Domain: `dvlab.contoso.local`
- NC URI: `https://dvlab-nc.dvlab.contoso.local`
- Servers: `DVLAB-S1-N01` through `DVLAB-S1-N04`
- Network Controllers: `DVLAB-NC01` through `DVLAB-NC03`
- Gateways: `DVLAB-GW01` through `DVLAB-GW03`
- Muxes: `DVLAB-MUX01`, `DVLAB-MUX02`

## Standard Get-SdnResource Mock

```powershell
Mock -ModuleName SdnDiagnostics Get-SdnResource {
    if (![string]::IsNullOrEmpty($ResourceRef)) {
        return $Global:PesterOfflineTests.SdnApiResourcesByRef[$ResourceRef]
    }
    else {
        return $Global:PesterOfflineTests.SdnApiResources[$ResourceType.ToString()]
    }
}
```

## After Creating Tests

- Verify the test file follows existing patterns in `tests/offline/`
- Confirm mock data references match files in `tests/offline/data/SdnApiResources/`
- Note: Tests require `.\build.ps1` to run (module must exist at `out/build/`)
