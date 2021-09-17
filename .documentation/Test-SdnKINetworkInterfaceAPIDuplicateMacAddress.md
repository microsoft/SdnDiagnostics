# Test-SdnKINetworkInterfaceAPIDuplicateMacAddress

## SYNOPSIS
Validate there are no adapters within the Network Controller Network Interfaces API that are duplicate.

## SYNTAX

```
Test-SdnKINetworkInterfaceAPIDuplicateMacAddress [[-NcUri] <Uri>] [[-NcRestCredential] <PSCredential>]
 [<CommonParameters>]
```

## DESCRIPTION
{{ Fill in the Description }}

## EXAMPLES

### EXAMPLE 1
```
Test-SdnKINetworkInterfaceAPIDuplicateMacAddress
```

### EXAMPLE 2
```
Test-SdnKINetworkInterfaceAPIDuplicateMacAddress -NcUri "https://nc.contoso.com"
```

### EXAMPLE 3
```
Test-SdnKINetworkInterfaceAPIDuplicateMacAddress -NcUri "https://nc.contoso.com" -NcRestCredential (Get-Credential)
```

## PARAMETERS

### -NcUri
Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.

```yaml
Type: Uri
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: $Global:SdnDiagnostics.EnvironmentInfo.NcUrl
Accept pipeline input: False
Accept wildcard characters: False
```

### -NcRestCredential
Specifies a user account that has permission to access the northbound NC API interface.
The default is the current user.

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
