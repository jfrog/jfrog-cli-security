package downloadstatus

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/gookit/color"
	"github.com/jedib0t/go-pretty/v6/text"
	artifactoryUtils "github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	corexray "github.com/jfrog/jfrog-cli-core/v2/utils/xray"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results/output"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
)

const (
	StatusBlocked = "BLOCKED"
	StatusAllowed = "ALLOWED"
	StatusUnknown = "UNKNOWN"

	artifactoryUrlMarker = "/artifactory/"
)

type DownloadStatusCommand struct {
	serverDetails  *config.ServerDetails
	repo           string
	pathCandidates []string
	outputFormat   format.OutputFormat
	project        string
}

func NewDownloadStatusCommand() *DownloadStatusCommand {
	return &DownloadStatusCommand{}
}

func (cmd *DownloadStatusCommand) SetServerDetails(server *config.ServerDetails) *DownloadStatusCommand {
	cmd.serverDetails = server
	return cmd
}

func (cmd *DownloadStatusCommand) SetRepoAndPathCandidates(repo string, pathCandidates []string) *DownloadStatusCommand {
	cmd.repo = repo
	cmd.pathCandidates = pathCandidates
	return cmd
}

func (cmd *DownloadStatusCommand) SetOutputFormat(outputFormat format.OutputFormat) *DownloadStatusCommand {
	cmd.outputFormat = outputFormat
	return cmd
}

func (cmd *DownloadStatusCommand) SetProject(project string) *DownloadStatusCommand {
	cmd.project = project
	return cmd
}

func (cmd *DownloadStatusCommand) ServerDetails() (*config.ServerDetails, error) {
	return cmd.serverDetails, nil
}

func (cmd *DownloadStatusCommand) CommandName() string {
	return "xr_download_status"
}

// ParseArtifact accepts a full platform URL (https://host/artifactory/repo/path), a bare 'repo/path' spec,
// or a docker pull reference ([registry-host/]repo/image[:tag|@sha256:digest]), and resolves it to a repo
// plus one or more candidate manifest paths to try (a tag can resolve to either a manifest list or a plain
// manifest, depending on how the image was pushed).
func ParseArtifact(arg string) (repo string, pathCandidates []string, err error) {
	spec := arg
	if schemeIdx := strings.Index(spec, "://"); schemeIdx != -1 {
		afterScheme := spec[schemeIdx+len("://"):]
		markerIdx := strings.Index(afterScheme, artifactoryUrlMarker)
		if markerIdx == -1 {
			return "", nil, errorutils.CheckErrorf("expected '%s' in the provided URL: %s", artifactoryUrlMarker, arg)
		}
		spec = afterScheme[markerIdx+len(artifactoryUrlMarker):]
	}
	if cut := strings.IndexAny(spec, "?#"); cut != -1 {
		spec = spec[:cut]
	}
	if decoded, unescapeErr := url.PathUnescape(spec); unescapeErr == nil {
		spec = decoded
	}
	spec = strings.Trim(spec, "/")

	if dockerRepo, dockerPaths, ok := parseDockerReference(spec); ok {
		return dockerRepo, dockerPaths, nil
	}

	repo, path, found := strings.Cut(spec, "/")
	if !found || repo == "" || path == "" {
		return "", nil, errorutils.CheckErrorf("expected '<repo>/<path>' or a full artifact URL, got: %s", arg)
	}
	return repo, []string{path}, nil
}

// parseDockerReference recognizes a docker pull-style reference by its trailing ':<tag>' or '@sha256:<digest>',
// strips a leading registry host if present, and maps it to the Artifactory storage path(s) for that image.
func parseDockerReference(spec string) (repo string, pathCandidates []string, ok bool) {
	lastSlash := strings.LastIndex(spec, "/")
	if lastSlash == -1 {
		return "", nil, false
	}
	lastSegment := spec[lastSlash+1:]

	var imageName, tag, digest string
	if atIdx := strings.Index(lastSegment, "@"); atIdx != -1 {
		imageName, digest = lastSegment[:atIdx], lastSegment[atIdx+1:]
		if colonIdx := strings.LastIndex(imageName, ":"); colonIdx != -1 {
			imageName = imageName[:colonIdx]
		}
		if imageName == "" || !strings.HasPrefix(digest, "sha256:") {
			return "", nil, false
		}
	} else if colonIdx := strings.LastIndex(lastSegment, ":"); colonIdx != -1 {
		imageName, tag = lastSegment[:colonIdx], lastSegment[colonIdx+1:]
		if imageName == "" || tag == "" {
			return "", nil, false
		}
	} else {
		return "", nil, false
	}

	repoAndImage := stripDockerRegistryHost(spec[:lastSlash]) + "/" + imageName
	repo, imagePath, found := strings.Cut(repoAndImage, "/")
	if !found || repo == "" || imagePath == "" {
		return "", nil, false
	}

	if digest != "" {
		// Artifactory stores digest path segments with ':' replaced by '__'.
		storageDigest := strings.Replace(digest, ":", "__", 1)
		return repo, []string{
			fmt.Sprintf("%s/%s/list.manifest.json", imagePath, storageDigest),
			fmt.Sprintf("%s/%s/manifest.json", imagePath, storageDigest),
			imagePath + "@" + digest,
		}, true
	}
	return repo, []string{
		fmt.Sprintf("%s/%s/list.manifest.json", imagePath, tag),
		fmt.Sprintf("%s/%s/manifest.json", imagePath, tag),
		imagePath + ":" + tag,
	}, true
}

// stripDockerRegistryHost drops a leading registry host segment, using the same heuristic docker itself
// uses: a first path element is a host if it contains a '.' or ':', or is exactly 'localhost'.
func stripDockerRegistryHost(prefix string) string {
	firstSegment, rest, found := strings.Cut(prefix, "/")
	if !found {
		return prefix
	}
	if strings.Contains(firstSegment, ".") || strings.Contains(firstSegment, ":") || firstSegment == "localhost" {
		return rest
	}
	return prefix
}

func (cmd *DownloadStatusCommand) Run() (err error) {
	path, sha256, err := cmd.resolveArtifact()
	if err != nil {
		return err
	}

	xrayManager, err := corexray.CreateXrayServiceManager(cmd.serverDetails, corexray.WithScopedProjectKey(cmd.project))
	if err != nil {
		return err
	}

	scanStatus, err := xrayManager.GetArtifactStatus(cmd.repo, path)
	if err != nil {
		return err
	}

	violationsResponse, err := xrayManager.GetViolations(
		xrayUtils.NewViolationsRequest().
			IncludeDetails(true).
			FilterByArtifacts(xrayUtils.ArtifactResourceFilter{Repository: cmd.repo, Path: path}),
	)
	if err != nil {
		return err
	}

	packageId, version, indexedSha256 := cmd.resolvePackageIdentity(xrayManager, path)
	var violations []services.XrayViolation
	if violationsResponse != nil {
		violations = violationsResponse.Violations
	}
	checksumMismatch := sha256 != "" && indexedSha256 != "" && !strings.EqualFold(sha256, indexedSha256)
	if checksumMismatch {
		violations = nil
	}
	result := buildResult(cmd.repo, path, sha256, cmd.serverDetails.Url, packageId, version, checksumMismatch, scanStatus, violations)
	return printResult(cmd.outputFormat, result)
}

// resolvePackageIdentity looks up how Xray identifies this artifact as a package (e.g. 'deb://debian:12:libxml2'),
// which the scans-list UI needs in its URL. Falls back to a generic identity if the artifact isn't a recognized
// package type or the lookup fails - the resulting link still works, just without the platform's stricter package
// context.
func (cmd *DownloadStatusCommand) resolvePackageIdentity(xrayManager *xray.XrayServicesManager, path string) (packageId, version, indexedSha256 string) {
	for _, candidate := range []string{cmd.repo + "/" + path, "default/" + cmd.repo + "/" + path} {
		summary, err := xrayManager.ArtifactSummary(services.ArtifactSummaryParams{Paths: []string{candidate}, CliCommand: "xr_status"})
		if err != nil || summary == nil || len(summary.Artifacts) == 0 {
			continue
		}
		general := summary.Artifacts[0].General
		pkgType := toXrayPkgPrefix(general.PkgType)
		name, version := splitPackageNameAndVersion(pkgType, general.ComponentId)
		return pkgType + "://" + name, version, general.Sha256
	}
	base := path
	if idx := strings.LastIndex(path, "/"); idx != -1 {
		base = path[idx+1:]
	}
	return "generic://" + base, "", ""
}

// toXrayPkgPrefix mirrors Xray's own package-type-to-URL-scheme mapping (e.g. Maven components are addressed
// as 'gav://', not 'maven://').
func toXrayPkgPrefix(pkgType string) string {
	lower := strings.ToLower(pkgType)
	if lower == "" {
		return "generic"
	}
	if lower == "maven" {
		return "gav"
	}
	return lower
}

// splitPackageNameAndVersion separates a component id's name from its version. Generic ids embed a
// checksum ('sha256:<hex>/name') rather than a version, so they stay unsplit.
func splitPackageNameAndVersion(pkgType, componentId string) (name, version string) {
	if schemeIdx := strings.Index(componentId, "://"); schemeIdx != -1 {
		componentId = componentId[schemeIdx+len("://"):]
	}
	if pkgType == "generic" || componentId == "" {
		return componentId, ""
	}
	colonIdx := strings.LastIndex(componentId, ":")
	if colonIdx <= 0 || componentId[colonIdx-1] == ':' {
		return componentId, ""
	}
	return componentId[:colonIdx], componentId[colonIdx+1:]
}

// resolveArtifact tries each path candidate in turn (a docker tag can resolve to a manifest list or a plain
// manifest) and returns the first one Artifactory actually has, along with its sha256.
func (cmd *DownloadStatusCommand) resolveArtifact() (path, sha256 string, err error) {
	artifactoryManager, err := artifactoryUtils.CreateServiceManager(cmd.serverDetails, -1, 0, false)
	if err != nil {
		return "", "", err
	}
	var lastErr error
	for _, candidate := range cmd.pathCandidates {
		fileInfo, ferr := artifactoryManager.FileInfo(cmd.repo + "/" + candidate)
		if ferr == nil {
			return candidate, fileInfo.Checksums.Sha256, nil
		}
		lastErr = ferr
	}
	if lastErr == nil {
		return "", "", errorutils.CheckErrorf("could not find artifact under repo '%s' (tried: %s)", cmd.repo, strings.Join(cmd.pathCandidates, ", "))
	}
	return "", "", errorutils.CheckErrorf("could not find artifact under repo '%s' (tried: %s): %s", cmd.repo, strings.Join(cmd.pathCandidates, ", "), lastErr.Error())
}

type violationRow struct {
	Watch            string
	Policy           string
	Rule             string
	Severity         string
	SeverityNumValue int `json:"-"`
	Blocking         bool
	Ignored          bool
	Detail           string
	ViolationId      string
	Link             string
}

type Result struct {
	Repo           string                          `json:"repo"`
	Path           string                          `json:"path"`
	Sha256         string                          `json:"sha256,omitempty"`
	ScansListLink  string                          `json:"scans_list_link,omitempty"`
	ScanStatus     services.ArtifactDetailedStatus `json:"scan_status"`
	DownloadStatus string                          `json:"download_status"`
	StatusReason   string                          `json:"status_reason,omitempty"`
	Violations     []violationRow                  `json:"violations"`
}

func buildResult(repo, path, sha256, platformUrl, packageId, version string, checksumMismatch bool, scanStatus *services.ArtifactStatusResponse, violations []services.XrayViolation) *Result {
	if scanStatus == nil {
		scanStatus = &services.ArtifactStatusResponse{}
	}
	result := &Result{
		Repo:          repo,
		Path:          path,
		Sha256:        sha256,
		ScansListLink: buildArtifactScansListLink(platformUrl, repo, path, packageId, version),
		ScanStatus:    scanStatus.Details,
		Violations:    []violationRow{},
	}

	artifactCompId := ""
	if packageId != "" && version != "" {
		artifactCompId = packageId + ":" + version
	}
	if checksumMismatch {
		violations = nil
	}

	blocking := false
	for _, violation := range violations {
		severity := severityutils.XraySeverityToSeverity(violation.Severity)
		severityNumValue := severityutils.GetSeverityDetails(severity, jasutils.NotScanned).Priority
		link := buildViolationUiLink(platformUrl, repo, path, packageId, version, artifactCompId, violation)
		for _, policy := range violation.Policies {
			row := violationRow{
				Watch:            violation.Watch,
				Policy:           policy.PolicyName,
				Rule:             policy.Rule,
				Severity:         string(violation.Severity),
				SeverityNumValue: severityNumValue,
				Blocking:         policy.IsBlocking && !policy.IsIgnored,
				Ignored:          policy.IsIgnored,
				Detail:           violationDetail(violation),
				ViolationId:      violation.IssueId,
				Link:             link,
			}
			blocking = blocking || row.Blocking
			result.Violations = append(result.Violations, row)
		}
	}

	sort.SliceStable(result.Violations, func(i, j int) bool {
		if result.Violations[i].Blocking != result.Violations[j].Blocking {
			return result.Violations[i].Blocking
		}
		return result.Violations[i].SeverityNumValue > result.Violations[j].SeverityNumValue
	})

	switch {
	case checksumMismatch:
		result.DownloadStatus = StatusUnknown
		result.StatusReason = "Xray's indexed checksum does not match this artifact"
	case blocking:
		result.DownloadStatus = StatusBlocked
		result.StatusReason = "one or more matched policies are configured to block downloads"
	case isScanIncomplete(scanStatus.Details.Violations):
		result.DownloadStatus = StatusUnknown
		result.StatusReason = scanIncompleteReason(scanStatus.Details.Violations.Status)
	default:
		result.DownloadStatus = StatusAllowed
	}
	return result
}

func violationDetail(violation services.XrayViolation) string {
	if violation.Summary != "" {
		return violation.Summary
	}
	if len(violation.Cves) > 0 && violation.Cves[0].Id != "" {
		return violation.Cves[0].Id
	}
	return violation.Description
}

// buildViolationUiLink builds a deep link into Xray's Scans List -> Violation Details view for this exact
// violation. This mirrors an internal URL scheme reverse-engineered from the Xray UI (not a documented/stable
// API), built around a JSON-encoded 'issue' query param the UI reads to open straight to this violation.
func buildViolationUiLink(platformUrl, repo, path, packageId, version, artifactCompId string, violation services.XrayViolation) string {
	issue := buildScansListIssue(violation, artifactCompId)
	issueJson, err := json.Marshal(issue)
	if err != nil {
		return ""
	}
	return buildScansListLink(platformUrl, repo, path, packageId, version, "violations", string(issueJson))
}

// buildArtifactScansListLink builds a link to the artifact's own page in Xray's Scans List tab (the overview
// for all of its results), as opposed to buildViolationUiLink which deep-links one specific violation.
func buildArtifactScansListLink(platformUrl, repo, path, packageId, version string) string {
	return buildScansListLink(platformUrl, repo, path, packageId, version, "overview", "")
}

func buildScansListLink(platformUrl, repo, path, packageId, version, pageType, issueJson string) string {
	if platformUrl == "" {
		return ""
	}

	query := url.Values{}
	if version != "" {
		query.Set("version", version)
	}
	query.Set("package_id", packageId)
	query.Set("path", repo+"/"+path)
	query.Set("page_type", pageType)
	if issueJson != "" {
		query.Set("issue", issueJson)
	}

	artifactName := path
	if idx := strings.LastIndex(path, "/"); idx != -1 {
		artifactName = path[idx+1:]
	}
	return fmt.Sprintf("%s/ui/scans-list/repositories/%s/scan-descendants/%s?%s",
		strings.TrimSuffix(platformUrl, "/"), url.PathEscape(repo), url.PathEscape(artifactName), query.Encode())
}

type scansListMatchedPolicy struct {
	Policy              string `json:"policy"`
	Rule                string `json:"rule"`
	IsBlocking          bool   `json:"is_blocking"`
	BlockingMask        int    `json:"blocking_mask"`
	IsSkipNotApplicable bool   `json:"is_skip_not_applicable"`
}

type scansListIssue struct {
	IsExposuresIssue     bool                     `json:"is_exposures_issue"`
	CompId               string                   `json:"comp_id"`
	IssueId              string                   `json:"issue_id"`
	UserIssueId          string                   `json:"user_issue_id"`
	WatcherName          string                   `json:"watcher_name"`
	SourceCompId         string                   `json:"source_comp_id"`
	Title                string                   `json:"title"`
	Type                 string                   `json:"type"`
	MatchedPolicies      []scansListMatchedPolicy `json:"matched_policies"`
	Severity             string                   `json:"severity"`
	ComponentPackageType string                   `json:"component_package_type"`
}

func buildScansListIssue(violation services.XrayViolation, artifactCompId string) scansListIssue {
	infected := ""
	if len(violation.InfectedComponentIds) > 0 {
		infected = violation.InfectedComponentIds[0]
	}
	compId := infected
	sourceCompId := infected
	if artifactCompId != "" && infected != "" && artifactCompId != infected {
		compId = artifactCompId
		sourceCompId = infected
	} else if compId == "" {
		compId = artifactCompId
		sourceCompId = artifactCompId
	}
	componentPackageType := ""
	if idx := strings.Index(compId, "://"); idx != -1 {
		componentPackageType = compId[:idx]
	}

	policies := make([]scansListMatchedPolicy, 0, len(violation.Policies))
	for _, policy := range violation.Policies {
		policies = append(policies, scansListMatchedPolicy{
			Policy:              policy.PolicyName,
			Rule:                policy.Rule,
			IsBlocking:          policy.IsBlocking,
			BlockingMask:        policy.BlockingMask,
			IsSkipNotApplicable: policy.SkipNotApplicable,
		})
	}

	return scansListIssue{
		IsExposuresIssue:     violation.ExposureDetails != nil,
		CompId:               compId,
		IssueId:              violation.IssueId,
		UserIssueId:          violation.Id,
		WatcherName:          violation.Watch,
		SourceCompId:         sourceCompId,
		Title:                violationDetail(violation),
		Type:                 strings.ToLower(string(violation.Type)),
		MatchedPolicies:      policies,
		Severity:             string(violation.Severity),
		ComponentPackageType: componentPackageType,
	}
}

func isScanIncomplete(status services.ArtifactScanStatus) bool {
	switch status.Status {
	case services.ArtifactStatusDone, services.ArtifactStatusNotSupported:
		return false
	default:
		return true
	}
}

func scanIncompleteReason(status services.ArtifactStatus) string {
	switch status {
	case services.ArtifactStatusFailed:
		return "violation scan failed, so download blocking cannot be determined"
	case services.ArtifactStatusPartial:
		return "violation scan is partial, so download blocking cannot be determined"
	default:
		return "violation scanning has not completed for this artifact yet. A policy that blocks unscanned artifacts can still block the download"
	}
}

func printResult(outputFormat format.OutputFormat, result *Result) error {
	if outputFormat == format.Json {
		return output.PrintJson(result)
	}

	log.Output(fmt.Sprintf("Artifact:         %s/%s", result.Repo, result.Path))
	if result.Sha256 != "" {
		log.Output(fmt.Sprintf("Sha256:           %s", result.Sha256))
	}
	log.Output(fmt.Sprintf("Violation Scan:   %s", result.ScanStatus.Violations.Status))
	log.Output(fmt.Sprintf("Download Status:  %s", colorizeDownloadStatus(result.DownloadStatus)))
	if result.StatusReason != "" {
		log.Output(fmt.Sprintf("Reason:           %s", result.StatusReason))
	}
	if result.ScansListLink != "" {
		log.Output(fmt.Sprintf("Results:          %s", result.ScansListLink))
	}

	// The Link column only earns its place when the terminal can actually render it as a clickable OSC 8
	// hyperlink (e.g. iTerm2, VS Code, Windows Terminal) - in a terminal that can't (e.g. Terminal.app), a
	// column that looks like a link but does nothing would be misleading, so it's dropped entirely instead.
	if terminalSupportsHyperlinks() {
		rows := make([]violationTableRowWithLink, 0, len(result.Violations))
		for _, violation := range result.Violations {
			common := newViolationTableRow(violation)
			rows = append(rows, violationTableRowWithLink{
				Blocking:    common.Blocking,
				Severity:    common.Severity,
				Detail:      common.Detail,
				State:       common.State,
				ViolationId: common.ViolationId,
				Watch:       common.Watch,
				Policy:      common.Policy,
				Rule:        common.Rule,
				Link:        text.Hyperlink(violation.Link, "Open ↗"),
			})
		}
		return coreutils.PrintTable(rows, "Violations", "No violations found for this artifact", true)
	}

	rows := make([]violationTableRow, 0, len(result.Violations))
	for _, violation := range result.Violations {
		rows = append(rows, newViolationTableRow(violation))
	}
	return coreutils.PrintTable(rows, "Violations", "No violations found for this artifact", true)
}

func newViolationTableRow(violation violationRow) violationTableRow {
	return violationTableRow{
		Blocking:    colorizeBlocking(violation.Blocking),
		Severity:    colorizeSeverity(violation.Severity),
		Detail:      violation.Detail,
		State:       violationState(violation.Ignored),
		ViolationId: violation.ViolationId,
		Watch:       violation.Watch,
		Policy:      violation.Policy,
		Rule:        violation.Rule,
	}
}

// terminalSupportsHyperlinks reports whether this process is attached to a terminal known to render OSC 8
// hyperlinks (not all terminals do - notably Terminal.app on macOS never implemented it).
func terminalSupportsHyperlinks() bool {
	if os.Getenv("WT_SESSION") != "" || os.Getenv("KITTY_WINDOW_ID") != "" {
		return true
	}
	switch os.Getenv("TERM_PROGRAM") {
	case "iTerm.app", "vscode", "Hyper", "WezTerm", "ghostty", "Tabby", "WarpTerminal":
		return true
	default:
		return false
	}
}

type violationTableRow struct {
	Blocking    string `col-name:"Blocking"`
	Severity    string `col-name:"Severity"`
	Detail      string `col-name:"Detail"`
	State       string `col-name:"State"`
	ViolationId string `col-name:"Violation ID"`
	Watch       string `col-name:"Watch"`
	Policy      string `col-name:"Policy"`
	Rule        string `col-name:"Rule"`
}

// violationTableRowWithLink mirrors violationTableRow exactly, plus Link. It's a separate, fully duplicated
// struct rather than one embedding the other - go-pretty's table reflection doesn't flatten anonymous
// embedded fields, so an embedded violationTableRow would render as a single blank, untagged column instead
// of promoting its fields.
type violationTableRowWithLink struct {
	Blocking    string `col-name:"Blocking"`
	Severity    string `col-name:"Severity"`
	Detail      string `col-name:"Detail"`
	State       string `col-name:"State"`
	ViolationId string `col-name:"Violation ID"`
	Watch       string `col-name:"Watch"`
	Policy      string `col-name:"Policy"`
	Rule        string `col-name:"Rule"`
	Link        string `col-name:"Link"`
}

func colorizeBlocking(blocking bool) string {
	if blocking {
		return color.New(color.FgRed, color.OpBold).Render("Yes")
	}
	return color.New(color.FgGreen).Render("No")
}

func colorizeSeverity(severity string) string {
	sev := severityutils.GetSeverity(severity)
	return severityutils.GetSeverityDetails(sev, jasutils.NotScanned).ToString(sev, true)
}

func violationState(ignored bool) string {
	if ignored {
		return "Ignored"
	}
	return "Active"
}

func colorizeDownloadStatus(status string) string {
	switch status {
	case StatusBlocked:
		return color.New(color.FgRed, color.OpBold).Render(status)
	case StatusAllowed:
		return color.New(color.FgGreen, color.OpBold).Render(status)
	default:
		return color.New(color.FgYellow, color.OpBold).Render(status)
	}
}
