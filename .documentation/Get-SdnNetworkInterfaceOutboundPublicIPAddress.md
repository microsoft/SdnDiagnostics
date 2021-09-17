# Get-SdnNetworkInterfaceOutboundPublicIPAddress

## SYNOPSIS
Gets the outbound public IP address that is used by a network interface.

## SYNTAX

```
Get-SdnNetworkInterfaceOutboundPublicIPAddress [-NcUri] <Uri> [-ResourceId] <String>
 [[-Credential] <PSCredential>] [<CommonParameters>]
```

## DESCRIPTION
{{ Fill in the Description }}

## EXAMPLES

### EXAMPLE 1
```
Get-SdnNetworkInterfaceOutboundPublicIPAddress -NcUri "https://nc.contoso.com" -ResourceId '8f9faf0a-837b-43cd-b4bf-dbe996993514'
```

### EXAMPLE 2
```
Get-SdnNetworkInterfaceOutboundPublicIPAddress -NcUri "https://nc.contoso.com" -ResourceId '8f9faf0a-837b-43cd-b4bf-dbe996993514' -Credential (Get-Credential)
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

### -ResourceId
Specifies the unique identifier for the networkinterface resource.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
Specifies a user account that has permission to perform this action.
The default is the current user.

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
