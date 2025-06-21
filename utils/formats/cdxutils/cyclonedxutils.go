package cdxutils

import (
	"path/filepath"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-security/utils"
)

const (
	// Indicates that the component is a root component in the BOM
	RootRelation ComponentRelation = "root"
	// Indicates that the component is a direct dependency of another component
	DirectRelation ComponentRelation = "direct_dependency"
	// Indicates that the component is a transitive dependency of another component
	TransitiveRelation ComponentRelation = "transitive_dependency"
	// Undefined relation
	UnknownRelation ComponentRelation = ""
)

type ComponentRelation string

// AppendProperties appends new properties to the existing properties list and returns the updated list.
func AppendProperties(properties *[]cyclonedx.Property, newProperties ...cyclonedx.Property) *[]cyclonedx.Property {
	for _, property := range newProperties {
		// Check if the property already exists
		if existingProperty := searchProperty(properties, property.Name); existingProperty != nil {
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
func searchProperty(properties *[]cyclonedx.Property, name string) *cyclonedx.Property {
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

func GetComponentRelation(bom *cyclonedx.BOM, componentRef string) ComponentRelation {
	if bom == nil {
		return UnknownRelation
	}
	// Calculate the root components
	for _, root := range GetRootDependenciesEntries(bom) {
		if root.Ref == componentRef {
			// The component is a root, hence it is a direct dependency
			return RootRelation
		}
		if root.Dependencies == nil || len(*root.Dependencies) == 0 {
			// No dependencies, continue to the next root
			continue
		}
		for _, directDependencyRef := range *root.Dependencies {
			if directDependencyRef == componentRef {
				// The component is a direct dependency of this root
				return DirectRelation
			}
		}
	}
	// No direct dependency found
	if SearchComponentByRef(bom.Components, componentRef) != nil {
		return TransitiveRelation
	}
	// reference not found in the BOM components or dependencies
	return UnknownRelation
}

func GetDirectDependencies(dependencies *[]cyclonedx.Dependency, ref string) []string {
	depEntry := SearchDependencyEntry(dependencies, ref)
	if depEntry == nil || depEntry.Dependencies == nil || len(*depEntry.Dependencies) == 0 {
		// No dependencies found for the given reference
		return []string{}
	}
	return *depEntry.Dependencies
}

func GetRootDependenciesEntries(bom *cyclonedx.BOM) (roots []cyclonedx.Dependency) {
	roots = []cyclonedx.Dependency{}
	if bom == nil {
		return
	}
	// Create a Set to track all references that are listed in `dependsOn`
	refs := datastructures.MakeSet[string]()
	dependedRefs := datastructures.MakeSet[string]()
	// Populate the maps
	if bom.Dependencies != nil {
		for _, dep := range *bom.Dependencies {
			refs.Add(dep.Ref)
			if dep.Ref == "" || dep.Dependencies == nil {
				// No dependencies, continue
				continue
			}
			for _, dependsOn := range *dep.Dependencies {
				dependedRefs.Add(dependsOn)
			}
		}
		// Identify root dependencies (those not listed in any `dependsOn`)
		for _, id := range refs.ToSlice() {
			if dep := SearchDependencyEntry(bom.Dependencies, id); dep != nil && !dependedRefs.Exists(dep.Ref) {
				// This is a root dependency, add it
				roots = append(roots, *dep)
			}
		}
	}
	if len(roots) == 0 && bom.Components != nil && len(*bom.Components) > 0 {
		for _, comp := range *bom.Components {
			if comp.BOMRef != "" && comp.Type == cyclonedx.ComponentTypeLibrary && !refs.Exists(comp.BOMRef) {
				// If no root dependencies were found, add all library components as roots
				roots = append(roots, cyclonedx.Dependency{Ref: comp.BOMRef})
			}
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
		BOMRef: getFileRef(filePathOrUri),
		Type:   cyclonedx.ComponentTypeFile,
		Name:   convertToFileUrlIfNeeded(filePathOrUri),
	}
	return
}

func getFileRef(filePathOrUri string) string {
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

func Exclude(bom *cyclonedx.BOM, components ...cyclonedx.Component) *cyclonedx.BOM {
	if bom == nil {
		return bom
	}
	filteredSbom := cyclonedx.NewBOM()
	filteredSbom.Components = excludeFromComponents(bom.Components, components...)
	filteredSbom.Dependencies = excludeFromDependencies(bom.Dependencies, components...)
	return filteredSbom
}

func excludeFromComponents(components *[]cyclonedx.Component, excludeComponents ...cyclonedx.Component) *[]cyclonedx.Component {
	if components == nil || len(*components) == 0 || len(excludeComponents) == 0 {
		return components
	}
	excludeRefs := datastructures.MakeSet[string]()
	for _, comp := range excludeComponents {
		excludeRefs.Add(comp.BOMRef)
	}
	filteredComponents := []cyclonedx.Component{}
	for _, comp := range *components {
		if !excludeRefs.Exists(comp.BOMRef) {
			filteredComponents = append(filteredComponents, comp)
		}
	}
	return &filteredComponents
}

func excludeFromDependencies(dependencies *[]cyclonedx.Dependency, excludeComponents ...cyclonedx.Component) *[]cyclonedx.Dependency {
	if dependencies == nil || len(*dependencies) == 0 || len(excludeComponents) == 0 {
		return dependencies
	}
	excludeRefs := datastructures.MakeSet[string]()
	for _, comp := range excludeComponents {
		excludeRefs.Add(comp.BOMRef)
	}
	filteredDependencies := []cyclonedx.Dependency{}
	for _, dep := range *dependencies {
		if excludeRefs.Exists(dep.Ref) {
			// This dependency is excluded, skip it
			continue
		}
		filteredDep := cyclonedx.Dependency{Ref: dep.Ref}
		depDirectDependencies := []string{}
		if dep.Dependencies != nil {
			// Also filter the components from the dependencies of this dependency
			for _, depRef := range *dep.Dependencies {
				if !excludeRefs.Exists(depRef) {
					depDirectDependencies = append(depDirectDependencies, depRef)
				}
			}
		}
		if len(depDirectDependencies) > 0 {
			filteredDep.Dependencies = &depDirectDependencies
		}
		filteredDependencies = append(filteredDependencies, filteredDep)
	}
	return &filteredDependencies
}
