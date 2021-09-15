---
external help file: SdnDiagnostics-help.xml
Module Name: SdnDiagnostics
online version:
schema: 2.0.0
---

# Convert-EtwTraceToTxt

## SYNOPSIS
Used to convert existing etw provider traces into text readable format

## SYNTAX

```
Convert-EtwTraceToTxt [-FileName] <FileInfo> [[-Destination] <FileInfo>] [[-Overwrite] <String>]
 [[-Report] <String>] [<CommonParameters>]
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

### -FileName
ETL trace file path and name to convert

```yaml
Type: FileInfo
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Destination
Output file name and directory.
If ommitted, will use the FileName path and base name.

```yaml
Type: FileInfo
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Overwrite
Overwrites existing files.
If ommitted, defaults to no.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: No
Accept pipeline input: False
Accept wildcard characters: False
```

### -Report
Generates an HTML report.
If ommitted, defaults to no.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: No
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
