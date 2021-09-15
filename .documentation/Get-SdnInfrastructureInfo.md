---
external help file: SdnDiagnostics-help.xml
Module Name: SdnDiagnostics
online version:
schema: 2.0.0
---

# Get-SdnInfrastructureInfo

## SYNOPSIS
Get the SDN Infrastrucutre Info based on one NC VM.
The function will update:
- $Global:SdnDiagnostics.EnvironmentInfo.NcUrl
- $Global:SdnDiagnostics.EnvironmentInfo.NC
- $Global:SdnDiagnostics.EnvironmentInfo.MUX
- $Global:SdnDiagnostics.EnvironmentInfo.Gateway
- $Global:SdnDiagnostics.EnvironmentInfo.Host

## SYNTAX

```
Get-SdnInfrastructureInfo [-NetworkController] <String> [[-Credential] <PSCredential>]
 [[-NcRestCredential] <PSCredential>] [<CommonParameters>]
```

## DESCRIPTION
{{ Fill in the Description }}

## EXAMPLES

### Example 1
```powershell
PS C:\> {{ Add example code here }}
```

{{ Add example description here }}

## PARAMETERS

### -NetworkController
{{ Fill NetworkController Description }}

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
The NC Admin Credential if different from current logon user credential.

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: [System.Management.Automation.PSCredential]::Empty
Accept pipeline input: False
Accept wildcard characters: False
```

### -NcRestCredential
The NC Rest API credential if different from current logon user credential.

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: [System.Management.Automation.PSCredential]::Empty
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
