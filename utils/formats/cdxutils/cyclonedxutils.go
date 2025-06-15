package cdxutils

import "github.com/CycloneDX/cyclonedx-go"

func AppendProperties(properties *[]cyclonedx.Property, newProperties ...cyclonedx.Property) *[]cyclonedx.Property {
	for _, property := range newProperties {
		// Check if the property already exists
		if existingProperty := SearchProperty(properties, property.Name); existingProperty != nil {
			// The property already exists
			continue
		}
		if properties == nil {
			properties = &[]cyclonedx.Property{}
		}
		// The property does not exist, append it to the list
		*properties = append(*properties, property)
	}
	return properties
}

func SearchProperty(properties *[]cyclonedx.Property, name string) *cyclonedx.Property {
	if properties == nil || len(*properties) == 0 {
		return nil
	}
	for _, property := range *properties {
		if property.Name == name {
			return &property
		}
	}
	return nil
}
