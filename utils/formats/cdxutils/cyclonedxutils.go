package cdxutils

import (
	"path/filepath"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-security/utils"
)

// AppendProperties appends new properties to the existing properties list.
// Returns the updated properties list.
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

// SearchProperty searches for a property by name in the provided properties list.
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

// SearchDependencyEntry searches for a dependency entry by reference in the provided dependencies list.
func SearchDependencyEntry(dependencies *[]cyclonedx.Dependency, ref string) *cyclonedx.Dependency {
	if dependencies == nil || len(*dependencies) == 0 {
		return nil
	}
	for _, dependency := range *dependencies {
		if dependency.Ref == ref {
			return &dependency
		}
	}
	return nil
}

// IsDirectDependency checks if a component is a direct dependency of a root component in the provided components and dependencies.
func IsDirectDependency(dependencies *[]cyclonedx.Dependency, ref string) bool {
	if dependencies == nil || len(*dependencies) == 0 {
		return false
	}
	for _, root := range GetRootDependenciesEntries(dependencies) {
		if root.Ref == ref {
			// The component is a root, hence it is not a direct dependency
			return false
		}
		if root.Dependencies == nil || len(*root.Dependencies) == 0 {
			// No dependencies, continue to the next root
			continue
		}
		for _, dep := range *root.Dependencies {
			if dep == ref {
				// The component is a direct dependency of this root
				return true
			}
		}
	}
	// No direct dependency found
	return false
}

func GetDirectDependencies(dependencies *[]cyclonedx.Dependency, ref string) (depRefs []string) {
	depEntry := SearchDependencyEntry(dependencies, ref)
	if depEntry == nil || depEntry.Dependencies == nil || len(*depEntry.Dependencies) == 0 {
		// No dependencies found for the given reference
		return
	}
	return *depEntry.Dependencies
}

func GetRootDependenciesEntries(dependencies *[]cyclonedx.Dependency) (roots []cyclonedx.Dependency) {
	roots = []cyclonedx.Dependency{}
	if dependencies == nil || len(*dependencies) == 0 {
		// If no dependencies are found, return an empty list
		return
	}
	// Create a Set to track all references that are listed in `dependsOn`
	refs := datastructures.MakeSet[string]()
	dependedRefs := datastructures.MakeSet[string]()
	// Populate the maps
	for _, dep := range *dependencies {
		if dep.Ref == "" || dep.Dependencies == nil {
			// No dependencies, continue
			continue
		}
		refs.Add(dep.Ref)
		for _, dependsOn := range *dep.Dependencies {
			dependedRefs.Add(dependsOn)
		}
	}
	// Identify root dependencies (those not listed in any `dependsOn`)
	for _, id := range refs.ToSlice() {
		if dep := SearchDependencyEntry(dependencies, id); dep != nil && !dependedRefs.Exists(dep.Ref) {
			// This is a root dependency, add it
			roots = append(roots, *dep)
		}
	}
	return
}

func SearchComponentByRef(components *[]cyclonedx.Component, ref string) (component *cyclonedx.Component) {
	if components == nil || len(*components) == 0 {
		return
	}
	for _, comp := range *components {
		if comp.BOMRef == ref {
			return &comp
		}
	}
	return
}

func CreateFileOrDirComponent(filePathOrUri string) (component cyclonedx.Component) {
	component = cyclonedx.Component{
		BOMRef: GetFileRef(filePathOrUri),
		Type:   cyclonedx.ComponentTypeFile,
		Name:   convertToFileUrlIfNeeded(filePathOrUri),
	}
	return
}

func GetFileRef(filePathOrUri string) string {
	uri := convertToFileUrlIfNeeded(filePathOrUri)
	wdRef, err := utils.Md5Hash(uri)
	if err != nil {
		return uri
	}
	return wdRef
}

func convertToFileUrlIfNeeded(location string) string {
	return filepath.ToSlash(location)
}
