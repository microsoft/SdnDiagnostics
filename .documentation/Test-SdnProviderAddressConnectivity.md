# Test-SdnProviderAddressConnectivity

## SYNOPSIS
Tests whether jumbo packets can be sent between the provider addresses on the current host to the remote provider addresses defined.

## SYNTAX

```
Test-SdnProviderAddressConnectivity [-ProviderAddress] <String[]> [<CommonParameters>]
```

## DESCRIPTION
{{ Fill in the Description }}

## EXAMPLES

### EXAMPLE 1
```
Test-SdnProviderAddressConnectivity -ProviderAddress (Get-SdnProviderAddress -ComputerName 'Server01','Server02')
```

## PARAMETERS

### -ProviderAddress
The IP address assigned to a hidden network adapter in a non-default network compartment.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
