package cdxutils

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"

	"github.com/jfrog/gofrog/datastructures"

	"github.com/jfrog/jfrog-client-go/utils/log"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

type FullBOM struct {
	cyclonedx.BOM
	Sast []*sarif.Run `json:"sast,omitempty"`
}

// Regular expression to match CWE IDs, which can be in the format "CWE-1234" or just "1234".
var cweSupportedPattern = regexp.MustCompile(`(?:CWE-)?(\d+)`)

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

func GetProperty(properties *[]cyclonedx.Property, name string) *cyclonedx.Property {
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

func GetComponentRelation(bom *cyclonedx.BOM, componentRef string, skipDefaultRoot bool) ComponentRelation {
	if bom == nil || bom.Components == nil {
		return UnknownRelation
	}
	component := SearchComponentByRef(bom.Components, componentRef)
	if component == nil || component.Type != cyclonedx.ComponentTypeLibrary {
		// The component is not found in the BOM components or not library, return UnknownRelation
		return UnknownRelation
	}
	dependencies := []cyclonedx.Dependency{}
	if bom.Dependencies != nil {
		dependencies = *bom.Dependencies
	}
	parents := SearchParents(componentRef, *bom.Components, dependencies...)
	// Calculate the root components
	for _, root := range GetRootDependenciesEntries(bom, skipDefaultRoot) {
		if root.Ref == componentRef {
			// The component is a root
			return RootRelation
		}
		if root.Dependencies == nil || len(*root.Dependencies) == 0 {
			// No dependencies, continue to the next root
			continue
		}
		for _, parentRef := range parents {
			if parentRef.BOMRef == root.Ref {
				// At least one of parents is a component that is a child of this root, hence it is a direct dependency
				return DirectRelation
			}
		}
	}
	// If we reach here, it means the component is not a root or not a child of a root component
	if len(parents) == 0 {
		// No parents found, the component is a direct dependency
		return DirectRelation
	}
	// Parents found, but not a root or direct dependency, hence it is a transitive dependency
	return TransitiveRelation
}

func SearchParents(componentRef string, components []cyclonedx.Component, dependencies ...cyclonedx.Dependency) []cyclonedx.Component {
	if len(dependencies) == 0 || len(components) == 0 {
		return []cyclonedx.Component{}
	}
	parents := []cyclonedx.Component{}
	for _, dependency := range dependencies {
		parents = append(parents, getDependencyComponentIfParent(componentRef, dependency, components)...)
	}
	return parents
}

func getDependencyComponentIfParent(componentRef string, dependency cyclonedx.Dependency, components []cyclonedx.Component) (parents []cyclonedx.Component) {
	parents = []cyclonedx.Component{}
	if dependency.Dependencies == nil || len(*dependency.Dependencies) == 0 {
		// No dependencies, no parents
		return
	}
	parentComponent := SearchComponentByRef(&components, dependency.Ref)
	if parentComponent == nil {
		return
	}
	if slices.Contains(*dependency.Dependencies, componentRef) {
		// The component is a child of this dependency, the dependency is a parent
		return append(parents, *parentComponent)
	}
	return
}

func GetDirectDependencies(dependencies *[]cyclonedx.Dependency, ref string) []string {
	depEntry := SearchDependencyEntry(dependencies, ref)
	if depEntry == nil || depEntry.Dependencies == nil || len(*depEntry.Dependencies) == 0 {
		// No dependencies found for the given reference
		return []string{}
	}
	return *depEntry.Dependencies
}

func GetRootDependenciesEntries(bom *cyclonedx.BOM, skipDefaultRoot bool) (roots []cyclonedx.Dependency) {
	roots = []cyclonedx.Dependency{}
	if bom == nil || bom.Components == nil || len(*bom.Components) == 0 {
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
				roots = append(roots, potentialRootDependencyToRoots(bom, *dep, skipDefaultRoot)...)
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

// For some technologies, inserting 'root' as dummy component, in this case the actual roots are the dependencies of this component.
func potentialRootDependencyToRoots(bom *cyclonedx.BOM, dependency cyclonedx.Dependency, skipDefaultRoot bool) (roots []cyclonedx.Dependency) {
	if strings.Contains(dependency.Ref, techutils.ToPackageRef("root","","")) && skipDefaultRoot {
		// dummy root, the actual roots are the dependencies of this component.
		roots = []cyclonedx.Dependency{}
		if dependency.Dependencies == nil || len(*dependency.Dependencies) == 0 {
			return
		}
		for _, dep := range *dependency.Dependencies {
			if found := SearchDependencyEntry(bom.Dependencies, dep); found != nil {
				roots = append(roots, *found)
			} else if found := SearchComponentByRef(bom.Components, dep); found != nil {
				// Root without dependencies
				roots = append(roots, cyclonedx.Dependency{Ref: found.BOMRef})
			}
		}
	}
	// This is a potential root dependency
	depComponent := SearchComponentByRef(bom.Components, dependency.Ref)
	if depComponent != nil && depComponent.Type == cyclonedx.ComponentTypeLibrary {
		// The component is the root
		return append(roots, dependency)
	}
	// In Xray-Lib-Plugin the root can be a file or directory component (the Metadata component) and the actual roots are the component children
	if depComponent != nil && depComponent.Type == cyclonedx.ComponentTypeLibrary {
		roots = append(roots, dependency)
	} else if bom.Metadata != nil && bom.Metadata.Component != nil && bom.Metadata.Component.BOMRef == dependency.Ref {
		for _, root := range *dependency.Dependencies {
			if rootDepEntry := SearchDependencyEntry(bom.Dependencies, root); rootDepEntry != nil {
				roots = append(roots, *rootDepEntry)
			}
		}
	}
	return
}

func SearchComponentByRef(components *[]cyclonedx.Component, ref string) (component *cyclonedx.Component) {
	if components == nil || len(*components) == 0 {
		return
	}
	for i, comp := range *components {
		if comp.BOMRef == ref {
			return &(*components)[i]
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
	return fmt.Sprintf("file:%s", wdRef)
}

func convertToFileUrlIfNeeded(location string) string {
	return filepath.ToSlash(location)
}

func ConvertToAffectedVersions(affectedComponent cyclonedx.Component, fixedVersion []string) *[]cyclonedx.AffectedVersions {
	if len(fixedVersion) == 0 {
		return nil
	}
	affected := CreateScaImpactedAffects(affectedComponent, fixedVersion)
	if affected.Range == nil {
		return nil
	}
	affectedVersions := []cyclonedx.AffectedVersions{}
	for _, version := range *affected.Range {
		if version.Status != cyclonedx.VulnerabilityStatusNotAffected {
			affectedVersions = append(affectedVersions, version)
		}
	}
	if len(affectedVersions) == 0 {
		return nil
	}
	return &affectedVersions
}

func Exclude(bom cyclonedx.BOM, componentsToExclude ...cyclonedx.Component) (filteredSbom *cyclonedx.BOM) {
	if bom.Components == nil || len(*bom.Components) == 0 || bom.Dependencies == nil || len(*bom.Dependencies) == 0 {
		// No components or dependencies to filter, return the original BOM
		return &bom
	}
	filteredSbom = &bom
	for _, compToExclude := range componentsToExclude {
		if matchedBomComp := SearchComponentByRef(bom.Components, compToExclude.BOMRef); matchedBomComp == nil || GetComponentRelation(&bom, matchedBomComp.BOMRef, false) == RootRelation {
			// If not a match or Root component, skip it
			continue
		}
		// Exclude the component from the dependencies
		filteredSbom.Dependencies = excludeFromDependencies(bom.Dependencies, compToExclude.BOMRef)
	}
	toExclude := datastructures.MakeSet[string]()
	for _, comp := range *filteredSbom.Components {
		if comp.Type != cyclonedx.ComponentTypeLibrary {
			// Only exclude library components
			continue
		}
		// Count the number of references to this component in the dependencies
		dependencyRefCount := 0
		for _, dependency := range *filteredSbom.Dependencies {
			if dependency.Ref == comp.BOMRef {
				// This dependency references the component, increment the count
				dependencyRefCount++
			}
			if dependency.Dependencies == nil || len(*dependency.Dependencies) == 0 {
				// No dependencies, continue to the next dependency
				continue
			}
			for _, depRef := range *dependency.Dependencies {
				if depRef == comp.BOMRef {
					// This dependency references the component, increment the count
					dependencyRefCount++
				}
			}
		}
		if dependencyRefCount == 0 {
			// This component is not referenced by any dependencies, mark it for exclusion
			toExclude.Add(comp.BOMRef)
		}
	}
	filteredSbom.Components = excludeFromComponents(bom.Components, toExclude.ToSlice()...)
	return filteredSbom
}

func excludeFromComponents(components *[]cyclonedx.Component, excludeComponents ...string) *[]cyclonedx.Component {
	if components == nil || len(*components) == 0 || len(excludeComponents) == 0 {
		return components
	}
	excludeRefs := datastructures.MakeSet[string]()
	for _, compRef := range excludeComponents {
		excludeRefs.Add(compRef)
	}
	filteredComponents := []cyclonedx.Component{}
	for _, comp := range *components {
		if !excludeRefs.Exists(comp.BOMRef) {
			filteredComponents = append(filteredComponents, comp)
		}
	}
	return &filteredComponents
}

func excludeFromDependencies(dependencies *[]cyclonedx.Dependency, excludeComponents ...string) *[]cyclonedx.Dependency {
	if dependencies == nil || len(*dependencies) == 0 || len(excludeComponents) == 0 {
		return dependencies
	}
	excludeRefs := datastructures.MakeSet[string]()
	for _, compRef := range excludeComponents {
		excludeRefs.Add(compRef)
	}
	filteredDependencies := []cyclonedx.Dependency{}
	for _, dep := range *dependencies {
		if excludeRefs.Exists(dep.Ref) {
			// This dependency is excluded, skip it
			continue
		}
		filteredDep := cyclonedx.Dependency{Ref: dep.Ref}
		if dep.Dependencies != nil {
			// Also filter the components from the dependencies of this dependency
			for _, depRef := range *dep.Dependencies {
				if !excludeRefs.Exists(depRef) {
					if filteredDep.Dependencies == nil {
						filteredDep.Dependencies = &[]string{}
					}
					*filteredDep.Dependencies = append(*filteredDep.Dependencies, depRef)
				}
			}
		}
		if filteredDep.Dependencies != nil && len(*filteredDep.Dependencies) > 0 {
			filteredDependencies = append(filteredDependencies, filteredDep)
		}
	}
	return &filteredDependencies
}

func AttachLicenseToComponent(component *cyclonedx.Component, license cyclonedx.LicenseChoice) {
	if component.Licenses == nil {
		component.Licenses = &cyclonedx.Licenses{}
	}
	// Check if the license already exists in the component
	if hasLicense(*component, license.License.ID) {
		// The license already exists, no need to add it again
		return
	}
	// Create a new license and add it to the component
	*component.Licenses = append(*component.Licenses, license)
}

func hasLicense(component cyclonedx.Component, licenseName string) bool {
	if component.Licenses == nil || len(*component.Licenses) == 0 {
		return false
	}
	for _, license := range *component.Licenses {
		if license.License != nil && license.License.ID == licenseName {
			return true
		}
	}
	return false
}

func AttachEvidenceOccurrenceToComponent(component *cyclonedx.Component, evidenceOccurrence cyclonedx.EvidenceOccurrence) {
	if component.Evidence == nil {
		component.Evidence = &cyclonedx.Evidence{}
	}
	if component.Evidence.Occurrences == nil {
		component.Evidence.Occurrences = &[]cyclonedx.EvidenceOccurrence{}
	}
	// Add the path as an occurrence
	*component.Evidence.Occurrences = append(*component.Evidence.Occurrences, evidenceOccurrence)
}

func AttachComponentAffects(issue *cyclonedx.Vulnerability, affectedComponent cyclonedx.Component, affectsGenerator func(affectedComponent cyclonedx.Component) cyclonedx.Affects, relatedProperties ...cyclonedx.Property) {
	if !HasImpactedAffects(*issue, affectedComponent) {
		// The affected component is not in the vulnerability, Add the affected component to the vulnerability
		if issue.Affects == nil {
			issue.Affects = &[]cyclonedx.Affects{}
		}
		*issue.Affects = append(*issue.Affects, affectsGenerator(affectedComponent))
	}
	if len(relatedProperties) == 0 {
		// No properties to add
		return
	}
	// Add the properties to the vulnerability
	issue.Properties = AppendProperties(issue.Properties, relatedProperties...)
}

func HasImpactedAffects(vulnerability cyclonedx.Vulnerability, affectedComponent cyclonedx.Component) bool {
	if vulnerability.Affects == nil {
		return false
	}
	for _, affected := range *vulnerability.Affects {
		if affected.Ref == affectedComponent.BOMRef {
			return true
		}
	}
	return false
}

func CreateScaImpactedAffects(impactedPackageComponent cyclonedx.Component, fixedVersions []string) (affect cyclonedx.Affects) {
	_, impactedPackageVersion, _ := techutils.SplitPackageURL(impactedPackageComponent.PackageURL)
	affect = cyclonedx.Affects{
		Ref:   impactedPackageComponent.BOMRef,
		Range: &[]cyclonedx.AffectedVersions{},
	}
	// Affected version
	*affect.Range = append(*affect.Range, cyclonedx.AffectedVersions{
		Version: impactedPackageVersion,
		Status:  cyclonedx.VulnerabilityStatusAffected,
	})
	// Fixed versions
	for _, fixedVersion := range fixedVersions {
		*affect.Range = append(*affect.Range, cyclonedx.AffectedVersions{
			Version: fixedVersion,
			Status:  cyclonedx.VulnerabilityStatusNotAffected,
		})
	}
	return
}

type CdxVulnerabilityParams struct {
	Ref         string
	ID          string
	Details     string
	Description string
	Service     *cyclonedx.Service
	CWE         []string
	References  []string
	Ratings     []cyclonedx.VulnerabilityRating
}

// Returns the index of the vulnerability in the BOM
func GetOrCreateScaIssue(destination *cyclonedx.BOM, params CdxVulnerabilityParams, properties ...cyclonedx.Property) (scaVulnerability *cyclonedx.Vulnerability) {
	if scaVulnerability = SearchVulnerabilityByRef(destination, params.Ref); scaVulnerability != nil {
		// The vulnerability already exists, update the ratings with the applicable status and attach properties if needed
		updateOrAppendVulnerabilitiesRatings(scaVulnerability, params.Ratings...)
		scaVulnerability.Properties = AppendProperties(scaVulnerability.Properties, properties...)
		return scaVulnerability
	}
	// Create a new SCA vulnerability, add it to the BOM
	if destination.Vulnerabilities == nil {
		destination.Vulnerabilities = &[]cyclonedx.Vulnerability{}
	}
	vulnerability := CreateBaseVulnerability(params, properties...)
	*destination.Vulnerabilities = append(*destination.Vulnerabilities, vulnerability)
	return &(*destination.Vulnerabilities)[len(*destination.Vulnerabilities)-1]
}

func CreateBaseVulnerability(params CdxVulnerabilityParams, properties ...cyclonedx.Property) cyclonedx.Vulnerability {
	var source *cyclonedx.Source
	if params.Service != nil {
		source = &cyclonedx.Source{
			Name: params.Service.Name,
		}
	}
	var ratings *[]cyclonedx.VulnerabilityRating
	if len(params.Ratings) > 0 {
		ratings = &params.Ratings
	}
	vuln := cyclonedx.Vulnerability{
		BOMRef:      params.Ref,
		ID:          params.ID,
		Source:      source,
		CWEs:        convertCweToCycloneDx(params.CWE),
		Description: params.Description,
		Detail:      params.Details,
		Ratings:     ratings,
		References:  getReferences(params.References),
	}
	vuln.Properties = AppendProperties(vuln.Properties, properties...)
	return vuln
}

func getReferences(references []string) *[]cyclonedx.VulnerabilityReference {
	if len(references) == 0 {
		return nil
	}
	refs := []cyclonedx.VulnerabilityReference{}
	for _, ref := range references {
		if ref == "" {
			continue
		}
		refs = append(refs, cyclonedx.VulnerabilityReference{
			Source: &cyclonedx.Source{
				URL: ref,
			},
		})
	}
	if len(refs) == 0 {
		// no valid references were found
		return nil
	}
	return &refs
}

func convertCweToCycloneDx(cwe []string) (cweList *[]int) {
	if len(cwe) == 0 {
		return nil
	}
	cweList = &[]int{}
	for _, cweId := range cwe {
		if cweInt, isSupportedCwe := extractCWENumber(cweId); !isSupportedCwe {
			log.Warn("Failed to parse CWE ID: ", cweId)
			continue
		} else {
			*cweList = append(*cweList, cweInt)
		}
	}
	return
}

func extractCWENumber(cweId string) (cweInt int, isSupportedCwe bool) {
	matches := cweSupportedPattern.FindStringSubmatch(cweId)
	if len(matches) < 2 {
		// No CWE id found
		return 0, false
	}
	cweID, err := strconv.Atoi(matches[1])
	return cweID, err == nil
}

func updateOrAppendVulnerabilitiesRatings(vulnerability *cyclonedx.Vulnerability, ratings ...cyclonedx.VulnerabilityRating) {
	if vulnerability == nil {
		return
	}
	// Check if the ratings already exist in the vulnerability
	for _, rating := range ratings {
		if existingRating := SearchRating(vulnerability.Ratings, rating.Method, rating.Source); existingRating != nil {
			// The rating already exists, update it
			if rating.Source != nil {
				existingRating.Source = rating.Source
			}
			if rating.Score != nil {
				existingRating.Score = rating.Score
			}
			if rating.Vector != "" {
				existingRating.Vector = rating.Vector
			}
			existingRating.Severity = rating.Severity
			continue
		}
		if vulnerability.Ratings == nil {
			vulnerability.Ratings = &[]cyclonedx.VulnerabilityRating{}
		}
		// The rating does not exist, append it to the vulnerability
		*vulnerability.Ratings = append(*vulnerability.Ratings, rating)
	}
}

func SearchRating(ratings *[]cyclonedx.VulnerabilityRating, method cyclonedx.ScoringMethod, sources ...*cyclonedx.Source) *cyclonedx.VulnerabilityRating {
	if ratings == nil || len(*ratings) == 0 {
		return nil
	}
	actualSources := []*cyclonedx.Source{}
	for _, source := range sources {
		if source != nil && source.Name != "" {
			actualSources = append(actualSources, source)
		}
	}
	for i := range *ratings {
		if (*ratings)[i].Method != method {
			continue // Skip if the method does not match
		}
		// If no sources are provided, return the first matching rating with the method
		if len(actualSources) == 0 {
			return &(*ratings)[i]
		}
		for _, source := range actualSources {
			// If the rating's source matches the provided source, return the rating
			if (*ratings)[i].Source != nil && source.Name == (*ratings)[i].Source.Name {
				// If the rating's source matches the provided source, return the rating
				return &(*ratings)[i]
			}
		}
	}
	return nil
}

func SearchVulnerabilityByRef(destination *cyclonedx.BOM, ref string) *cyclonedx.Vulnerability {
	if destination == nil || destination.Vulnerabilities == nil {
		return nil
	}
	for i := range *destination.Vulnerabilities {
		if (*destination.Vulnerabilities)[i].BOMRef == ref {
			return &(*destination.Vulnerabilities)[i]
		}
	}

	return nil
}

func GetSerialNumber(id string) string {
	if id == "" {
		id = uuid.New().String()
	}
	return fmt.Sprintf("urn:uuid:%s", id)
}

func AddServiceToBomIfNotExists(bom *cyclonedx.BOM, service cyclonedx.Service) {
	if SearchForServiceByName(bom, service.Name) != nil || bom == nil {
		return // Service already exists
	}
	// Add the service to the BOM
	if bom.Metadata == nil {
		bom.Metadata = &cyclonedx.Metadata{}
	}
	if bom.Metadata.Tools == nil {
		bom.Metadata.Tools = &cyclonedx.ToolsChoice{}
	}
	if bom.Metadata.Tools.Services == nil {
		bom.Metadata.Tools.Services = &[]cyclonedx.Service{}
	}
	*bom.Metadata.Tools.Services = append(*bom.Metadata.Tools.Services, service)
}

func SearchForServiceByName(bom *cyclonedx.BOM, serviceName string) *cyclonedx.Service {
	if bom == nil || bom.Metadata == nil || bom.Metadata.Tools == nil || bom.Metadata.Tools.Services == nil {
		return nil
	}
	for i := range *bom.Metadata.Tools.Services {
		if (*bom.Metadata.Tools.Services)[i].Name == serviceName {
			return &(*bom.Metadata.Tools.Services)[i]
		}
	}
	return nil
}

func AppendComponents(bom *cyclonedx.BOM, components *[]cyclonedx.Component) {
	if bom == nil || components == nil || len(*components) == 0 {
		return
	}
	if bom.Components == nil {
		bom.Components = &[]cyclonedx.Component{}
	}
	for _, component := range *components {
		if SearchComponentByRef(bom.Components, component.BOMRef) != nil {
			// The component already exists, skip it
			continue
		}
		*bom.Components = append(*bom.Components, component)
	}
}

func AppendDependencies(bom *cyclonedx.BOM, dependencies *[]cyclonedx.Dependency) {
	if bom == nil || dependencies == nil || len(*dependencies) == 0 {
		return
	}
	if bom.Dependencies == nil {
		bom.Dependencies = &[]cyclonedx.Dependency{}
	}
	for _, dependency := range *dependencies {
		if dependency.Dependencies == nil || len(*dependency.Dependencies) == 0 {
			// The dependency entry has no dependencies, skip it
			continue
		}
		existingDependency := SearchDependencyEntry(bom.Dependencies, dependency.Ref)
		if existingDependency == nil {
			// The dependency does not exist, add it to the BOM
			*bom.Dependencies = append(*bom.Dependencies, dependency)
			continue
		}
		// If the dependency already exists, we need to update its dependencies
		for _, depRef := range *dependency.Dependencies {
			if !slices.Contains(*existingDependency.Dependencies, depRef) {
				// The dependency reference does not exist in the existing dependency, add it
				if existingDependency.Dependencies == nil {
					existingDependency.Dependencies = &[]string{}
				}
				*existingDependency.Dependencies = append(*existingDependency.Dependencies, depRef)
			}
		}
	}
}
