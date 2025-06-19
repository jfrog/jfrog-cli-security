package cdxutils

import (
	"github.com/CycloneDX/cyclonedx-go"

	"github.com/jfrog/gofrog/datastructures"
)

// AppendProperties appends new properties to the existing properties list and returns the updated list.
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
	if properties == nil || len(*properties) == 0 || name == "" {
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

// IsDirectDependency checks if a component is a direct dependency given a list of dependencies and the component's reference.
func IsDirectDependency(dependencies *[]cyclonedx.Dependency, componentRef string) bool {
	if dependencies == nil || len(*dependencies) == 0 {
		return false
	}
	// Calculate the root components
	for _, root := range GetRootDependenciesEntries(dependencies) {
		if root.Ref == componentRef {
			// The component is a root, hence it is not a direct dependency
			return false
		}
		if root.Dependencies == nil || len(*root.Dependencies) == 0 {
			// No dependencies, continue to the next root
			continue
		}
		for _, directDependencyRef := range *root.Dependencies {
			if directDependencyRef == componentRef {
				// The component is a direct dependency of this root
				return true
			}
		}
	}
	// No direct dependency found
	return false
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
