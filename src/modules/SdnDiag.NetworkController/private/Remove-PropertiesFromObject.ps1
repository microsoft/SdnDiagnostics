function Remove-PropertiesFromObject {
    <#
        .SYNSOPSIS
        Removes properties from a PSObject.
    #>

    param(
        [Parameter(Mandatory=$true)]
        [PSObject]$Object,

        [Parameter(Mandatory=$true)]
        [string[]]$PropertiesToRemove
    )

    # Loop through each property of the object
    foreach ($property in $Object.PSObject.Properties) {

        # If the property is in the list of properties to remove, remove it
        if ($property.Name -in $PropertiesToRemove) {
            $Object.PSObject.Properties.Remove($property.Name)
        }
    }

    return $Object
}
