[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/microsoft/SdnDiagnostics/badge)](https://scorecard.dev/viewer/?uri=github.com/microsoft/SdnDiagnostics) ![](https://github.com/microsoft/SdnDiagnostics/actions/workflows/dependency-review.yml/badge.svg) ![](https://github.com/microsoft/SdnDiagnostics/actions/workflows/powershell.yml/badge.svg)

# Project
SdnDiagnostics is a PowerShell module that is designed to simplify the diagnostic troubleshooting and data collection process when troubleshooting issues related to [Microsoft Software Defined Network](https://docs.microsoft.com/en-us/windows-server/networking/sdn/software-defined-networking).

Please refer to the [wiki](https://github.com/microsoft/SdnDiagnostics/wiki) on how to install and use SdnDiagnostics in your environment.

## Structured diagnostics

Add the independent structured diagnostics stage to a normal SDN collection with
`-IncludeStructuredDiagnostics`:

```powershell
Start-SdnDataCollection -NetworkController 'NC01' -Role Server `
    -IncludeStructuredDiagnostics -IncludeLogs -Credential (Get-Credential)
```

The existing configuration-state and log APIs are unchanged. The separate stage
selects Server hosts from the chosen SDN nodes, including hosts with multiple roles,
and verifies Hyper-V before running collectors on each target. Structured collection
remains opt-in; duplicate queries between the legacy and structured collectors are
intentional.

Without Network Controller context, the same entry point collects structured data
without attempting NC discovery, Service Fabric manifests or NC REST requests:

```powershell
# Resolve all local Windows cluster nodes, or the local host if not clustered.
Start-SdnDataCollection -Role Server -OutputDirectory 'C:\Temp' `
    -IncludeStructuredDiagnostics

# Use all explicitly supplied hosts without expanding or replacing the list.
Start-SdnDataCollection -ComputerName 'Host01','Host02' -OutputDirectory 'C:\Temp' `
    -IncludeStructuredDiagnostics -IncludeLogs -FromDate (Get-Date).AddHours(-4) `
    -Credential (Get-Credential)
```

- The structured-only route requires the switch, no explicit `NetworkController` or
  `NcUri`, and no locally detected NC role. An explicitly supplied or locally detected
  NC retains normal discovery and error reporting; discovery failures do not silently
  fall back to a host-only collection.
- For non-NC `-Role Server` collection, configured Windows cluster membership is checked
  before enumerating its nodes. All resolved nodes, including down nodes, are retained;
  the existing role `-Limit` applies (default 16). Increase it when collecting a larger
  cluster. Enumeration failures do not fall back to localhost. Without cluster
  membership, collection uses the local host. Other roles require NC context.
- Explicit `ComputerName` lists are deduplicated and are not subject to the role limit.
  Each target must be a Hyper-V host; an empty host does not need existing VMs or an NC
  registration. Non-host targets fail the host check before collectors run.
- Structured-only collection returns its manifest result (`Status`, `OutputRoot`,
  `ManifestPath`, and `Nodes`). With SDN, the existing summary is returned and its
  `StructuredDiagnostics` property contains the structured result. Partial structured
  results do not discard otherwise successful SDN output. `IncludeNetView` applies
  only to normal SDN collection.
- Output is separate under
  `SdnDataCollection_<timestamp>\StructuredDiagnostics\<ComputerName>`.
  `ClusterCollectionManifest.json` summarizes the collection, while each node's
  `CollectionManifest.json` describes outcomes, artifacts, counts and truncation.
- The catalog covers host inventory, adapters, TCP/IP, DNS, Hyper-V, clusters, SMB,
  QoS and Network ATC. Remote jobs start before local collection, and remote nodes
  and collector groups run concurrently. Unavailable commands are recorded in the
  manifest. An ordinary Windows failover cluster does not require an NC deployment.
- `IncludeLogs` enables Network ATC events and setup-log copies. Events respect the
  requested dates with a 10 MiB cap per channel; setup logs retain the newest 5 MiB.
  Performance history uses relative duration buckets, not an exact historical window.
- Structured records use JSON arrays. ATC event files contain one JSON object per line,
  using the catalog's `.json` filenames. Legacy SDN serializers are unchanged.
- Remote targets need SdnDiagnostics installed, administrative access and WinRM;
  local structured collection does not require WinRM.
  Remote staging uses `StructuredDiagnostics_Staging\<SdnDataCollection_timestamp>`
  in SDN's working directory, separate from `Temp`. Detected retrieval failures
  retain staging. Each collector group writes one completion message for its node.

Collected diagnostics can include customer configuration, VM/process identifiers, SMB
sessions, DNS cache entries, firewall configuration, and event messages. Review artifacts
before sharing them. Optional platform cmdlets must be installed on targets.

Offline tests use `.\build.ps1` followed by `.\tests\offline\RunTests.ps1`.
The runner also accepts `-ModulePath` for an isolated build and a `-TestFile` array
to select the Server, structured collector and data-collection tests together.

## Package Statistics
| Package Gallery | Total Downloads | Current Version |
| :-- | :-- | :-- |
| PowerShell Gallery | [![downloads](https://img.shields.io/powershellgallery/dt/SdnDiagnostics.svg?label=Downloads)](https://www.powershellgallery.com/packages/SdnDiagnostics) | [![downloads](https://img.shields.io/powershellgallery/v/SdnDiagnostics.svg?label=Version)](https://www.powershellgallery.com/packages/SdnDiagnostics) |
| NuGet | [![downloads](https://img.shields.io/nuget/dt/SdnDiagnostics.svg?label=Downloads)](https://www.nuget.org/packages/SdnDiagnostics) |[![downloads](https://img.shields.io/nuget/v/SdnDiagnostics.svg?label=Version)](https://www.nuget.org/packages/SdnDiagnostics)

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

To get started on contributing to this module, refer to the [contributing](https://github.com/microsoft/SdnDiagnostics/blob/main/.github/contributing.md) guide on this project.
# Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
