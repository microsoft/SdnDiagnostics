# Get-SdnServiceFabricLog

## SYNOPSIS
Collect the default enabled logs from Service Fabric folder

## SYNTAX

```
Get-SdnServiceFabricLog [-OutputDirectory] <FileInfo> [[-FromDate] <DateTime>] [<CommonParameters>]
```

## DESCRIPTION
{{ Fill in the Description }}

## EXAMPLES

### EXAMPLE 1
```
Get-SdnServiceFabricLog -OutputDirectory "C:\Temp\CSS_SDN\SFLogs"
```

### EXAMPLE 2
```
Get-SdnServiceFabricLog -OutputDirectory "C:\Temp\CSS_SDN\SFLogs" -FromDate (Get-Date).AddHours(-1)
```

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

### -FromDate
Optional parameter that allows you to control how many hours worth of logs to retrieve from the system for the roles identified.
Default is 4 hours.

```yaml
Type: DateTime
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: (Get-Date).AddHours(-4)
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
