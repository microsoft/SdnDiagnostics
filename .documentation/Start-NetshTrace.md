# Start-NetshTrace

## SYNOPSIS
Enables netsh tracing.
Supports pre-configured trace providers or custom provider strings.

## SYNTAX

```
Start-NetshTrace [-OutputDirectory] <FileInfo> [[-TraceProviderString] <String>] [[-MaxTraceSize] <Int32>]
 [[-Capture] <String>] [[-Overwrite] <String>] [[-Report] <String>] [<CommonParameters>]
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

### -OutputDirectory
Specifies a specific path and folder in which to save the files.

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

### -TraceProviderString
The trace providers in string format that you want to trace on.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MaxTraceSize
Optional.
Specifies the maximum size in MB for saved trace files.
If unspecified, the default is 1024.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: 1024
Accept pipeline input: False
Accept wildcard characters: False
```

### -Capture
Optional.
Specifies whether packet capture is enabled in addition to trace events.
If unspecified, the default is No.

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

### -Overwrite
Optional.
Specifies whether this instance of the trace conversion command overwrites files that were rendered from previous trace conversions.
If unspecified, the default is Yes.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: Yes
Accept pipeline input: False
Accept wildcard characters: False
```

### -Report
Optional.
Specifies whether a complementing report will be generated in addition to the trace file report.
If unspecified, the default is disabled.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 6
Default value: Disabled
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
