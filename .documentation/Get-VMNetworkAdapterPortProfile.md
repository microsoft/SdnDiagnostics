# Get-VMNetworkAdapterPortProfile

## SYNOPSIS
Retrieves the port profile applied to the virtual machine network interfaces.

## SYNTAX

### SingleVM (Default)
```
Get-VMNetworkAdapterPortProfile -VMName <String> [-PortProfileFeatureId <Guid>] [<CommonParameters>]
```

### AllVMs
```
Get-VMNetworkAdapterPortProfile [-AllVMs] [-PortProfileFeatureId <Guid>] [<CommonParameters>]
```

## DESCRIPTION
{{ Fill in the Description }}

## EXAMPLES

### EXAMPLE 1
```
Get-VMNetworkAdapterPortProfile -VMName 'VM01'
```

### EXAMPLE 2
```
Get-VMNetworkAdapterPortProfile -AllVMs
```

## PARAMETERS

### -VMName
Specifies the name of the virtual machine to be retrieved.

```yaml
Type: String
Parameter Sets: SingleVM
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AllVMs
Switch to indicate to get all the virtual machines network interfaces on the hypervisor host.

```yaml
Type: SwitchParameter
Parameter Sets: AllVMs
Aliases:

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -PortProfileFeatureId
Specifies the unique identifier of the feature supported by the virtual switch extension.
If omitted, defaults to 9940cd46-8b06-43bb-b9d5-93d50381fd56.

```yaml
Type: Guid
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 9940cd46-8b06-43bb-b9d5-93d50381fd56
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
