---
external help file: SdnDiagnostics-help.xml
Module Name: SdnDiagnostics
online version:
schema: 2.0.0
---

# Get-SdnNetworkControllerState

## SYNOPSIS
Gathers the IMOS dump files from each of the Network Controllers

## SYNTAX

```
Get-SdnNetworkControllerState [-NcUri] <Uri> [-NetworkController] <String[]> [-OutputDirectory] <FileInfo>
 [[-Credential] <PSCredential>] [[-NcRestCredential] <PSCredential>] [[-ExecutionTimeOut] <Int32>]
 [<CommonParameters>]
```

## DESCRIPTION
{{ Fill in the Description }}

## EXAMPLES

### EXAMPLE 1
```
Get-SdnNcImosDumpFiles -NcUri "https://nc.contoso.com" -ComputerName $NetworkControllers -OutputDirectory "C:\Temp\CSS_SDN"
```

## PARAMETERS

### -NcUri
Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.

```yaml
Type: Uri
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -NetworkController
The computer name(s) of the Network Controllers that the IMOS dump files need to be collected from

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OutputDirectory
Directory location to save results.
By default it will create a new sub-folder called NetworkControllerState that the files will be copied to

```yaml
Type: FileInfo
Parameter Sets: (All)
Aliases:

Required: True
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
{{ Fill Credential Description }}

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: [System.Management.Automation.PSCredential]::Empty
Accept pipeline input: False
Accept wildcard characters: False
```

### -NcRestCredential
{{ Fill NcRestCredential Description }}

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: [System.Management.Automation.PSCredential]::Empty
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExecutionTimeOut
Specify the execution timeout (seconds) on how long you want to wait for operation to complete before cancelling operation
Default: 300

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 6
Default value: 300
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
