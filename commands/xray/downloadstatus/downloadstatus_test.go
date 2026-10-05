package downloadstatus

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/stretchr/testify/assert"
)

func TestParseArtifact(t *testing.T) {
	tests := []struct {
		name          string
		arg           string
		platformUrl   string
		expectedRepo  string
		expectedPaths []string
		expectError   bool
		forbiddenErr  string
	}{
		{name: "bare repo/path", arg: "libs-release-local/com/acme/foo-1.2.jar", expectedRepo: "libs-release-local", expectedPaths: []string{"com/acme/foo-1.2.jar"}},
		{name: "full url", arg: "https://acme.jfrog.io/artifactory/libs-release-local/com/acme/foo-1.2.jar", expectedRepo: "libs-release-local", expectedPaths: []string{"com/acme/foo-1.2.jar"}},
		{name: "leading and trailing slashes", arg: "/libs-release-local/com/acme/foo-1.2.jar/", expectedRepo: "libs-release-local", expectedPaths: []string{"com/acme/foo-1.2.jar"}},
		{name: "url missing artifactory marker", arg: "https://acme.jfrog.io/libs-release-local/foo.jar", expectError: true},
		{name: "missing path", arg: "libs-release-local", expectError: true},
		{name: "empty", arg: "", expectError: true},
		{
			name:          "docker pull reference with host",
			arg:           "xray-dev.jfrogdev.org/my-docker-repo/my-image:3",
			expectedRepo:  "my-docker-repo",
			expectedPaths: []string{"my-image/3/list.manifest.json", "my-image/3/manifest.json", "my-image:3"},
		},
		{
			name:          "docker pull reference without host",
			arg:           "my-docker-repo/my-image:3",
			expectedRepo:  "my-docker-repo",
			expectedPaths: []string{"my-image/3/list.manifest.json", "my-image/3/manifest.json", "my-image:3"},
		},
		{
			name:          "docker pull reference with nested image path",
			arg:           "xray-dev.jfrogdev.org/my-docker-repo/team/my-image:3",
			expectedRepo:  "my-docker-repo",
			expectedPaths: []string{"team/my-image/3/list.manifest.json", "team/my-image/3/manifest.json", "team/my-image:3"},
		},
		{
			name:          "docker reference with digest",
			arg:           "xray-dev.jfrogdev.org/my-docker-repo/my-image@sha256:abcd1234",
			expectedRepo:  "my-docker-repo",
			expectedPaths: []string{"my-image/sha256__abcd1234/list.manifest.json", "my-image/sha256__abcd1234/manifest.json", "my-image@sha256:abcd1234"},
		},
		{
			name:          "docker reference with tag and digest",
			arg:           "my-docker-repo/my-image:3@sha256:abcd1234",
			expectedRepo:  "my-docker-repo",
			expectedPaths: []string{"my-image/sha256__abcd1234/list.manifest.json", "my-image/sha256__abcd1234/manifest.json", "my-image@sha256:abcd1234"},
		},
		{
			name:          "filename containing a colon keeps the literal path",
			arg:           "libs-release-local/backup:latest.tar",
			expectedRepo:  "libs-release-local",
			expectedPaths: []string{"backup/latest.tar/list.manifest.json", "backup/latest.tar/manifest.json", "backup:latest.tar"},
		},
		{
			name:          "url query and fragment are stripped",
			arg:           "https://acme.jfrog.io/artifactory/libs-release-local/com/acme/foo-1.2.jar?tab=xray#violations",
			expectedRepo:  "libs-release-local",
			expectedPaths: []string{"com/acme/foo-1.2.jar"},
		},
		{
			name:          "url encoded path",
			arg:           "https://acme.jfrog.io/artifactory/libs-release-local/com%2Facme%2Ffoo-1.2.jar",
			expectedRepo:  "libs-release-local",
			expectedPaths: []string{"com/acme/foo-1.2.jar"},
		},
		{
			name:          "docker subdomain reference",
			arg:           "mycompany-docker-local.jfrog.io/nginx:1.25",
			platformUrl:   "https://mycompany.jfrog.io/artifactory",
			expectedRepo:  "docker-local",
			expectedPaths: []string{"nginx/1.25/list.manifest.json", "nginx/1.25/manifest.json", "nginx:1.25"},
		},
		{
			name:          "docker port reference",
			arg:           "artifactory.example.com:25000/nginx:1.25",
			platformUrl:   "https://artifactory.example.com:8081/artifactory",
			expectedRepo:  "25000",
			expectedPaths: []string{"nginx/1.25/list.manifest.json", "nginx/1.25/manifest.json", "nginx:1.25"},
		},
		{
			name:         "url with userinfo is redacted",
			arg:          "https://user:s3cret@acme.jfrog.io/ui/repo/file.jar",
			expectError:  true,
			forbiddenErr: "s3cret",
		},
		{
			name:         "query token is redacted",
			arg:          "libs-release-local?token=s3cret",
			expectError:  true,
			forbiddenErr: "s3cret",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repo, paths, err := ParseArtifact(test.arg, test.platformUrl)
			if test.expectError {
				assert.Error(t, err)
				if test.forbiddenErr != "" {
					assert.NotContains(t, err.Error(), test.forbiddenErr)
				}
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, test.expectedRepo, repo)
			assert.Equal(t, test.expectedPaths, paths)
		})
	}
}

func TestBuildResultBlockedByViolation(t *testing.T) {
	scanStatus := &services.ArtifactStatusResponse{Details: services.ArtifactDetailedStatus{
		Violations: services.ArtifactScanStatus{Status: services.ArtifactStatusDone},
	}}
	violations := []services.XrayViolation{{
		Watch:    "prod-watch",
		Severity: "Critical",
		Policies: []services.ViolationPolicy{{PolicyName: "no-critical-cve", Rule: "critical-cve", IsBlocking: true}},
	}}

	result := buildResult("libs-release-local", "com/acme/foo-1.2.jar", "sha", "https://acme.jfrog.io", "deb://debian:12:libxml2", "", false, scanStatus, violations)

	assert.Equal(t, StatusBlocked, result.DownloadStatus)
	assert.Len(t, result.Violations, 1)
	assert.True(t, result.Violations[0].Blocking)
}

func TestBuildResultIgnoredViolationDoesNotBlock(t *testing.T) {
	scanStatus := &services.ArtifactStatusResponse{Details: services.ArtifactDetailedStatus{
		Violations: services.ArtifactScanStatus{Status: services.ArtifactStatusDone},
	}}
	violations := []services.XrayViolation{{
		Watch:    "prod-watch",
		Severity: "Critical",
		Policies: []services.ViolationPolicy{{PolicyName: "no-critical-cve", Rule: "critical-cve", IsBlocking: true, IsIgnored: true}},
	}}

	result := buildResult("libs-release-local", "com/acme/foo-1.2.jar", "sha", "https://acme.jfrog.io", "deb://debian:12:libxml2", "", false, scanStatus, violations)

	assert.Equal(t, StatusAllowed, result.DownloadStatus)
	assert.False(t, result.Violations[0].Blocking)
	assert.True(t, result.Violations[0].Ignored)
}

func TestBuildResultPendingScanIsUnknown(t *testing.T) {
	scanStatus := &services.ArtifactStatusResponse{Details: services.ArtifactDetailedStatus{
		Violations: services.ArtifactScanStatus{Status: services.ArtifactStatusPending},
	}}

	result := buildResult("libs-release-local", "com/acme/foo-1.2.jar", "sha", "https://acme.jfrog.io", "deb://debian:12:libxml2", "", false, scanStatus, nil)

	assert.Equal(t, StatusUnknown, result.DownloadStatus)
}

func TestBuildResultCarriesViolationIdAndLink(t *testing.T) {
	scanStatus := &services.ArtifactStatusResponse{Details: services.ArtifactDetailedStatus{
		Violations: services.ArtifactScanStatus{Status: services.ArtifactStatusDone},
	}}
	violations := []services.XrayViolation{{
		Watch:                "prod-watch",
		Severity:             "Critical",
		IssueId:              "XRAY-94620",
		Id:                   "2096396277312823296",
		Type:                 "Security",
		InfectedComponentIds: []string{"deb://debian:12:libxml2:2.9.14+dfsg-1.3~deb12u4"},
		Policies:             []services.ViolationPolicy{{PolicyName: "no-critical-cve", Rule: "critical-cve", IsBlocking: true, BlockingMask: 1}},
	}}

	result := buildResult("bella-test-proj-gel-local", "libxml2_2.9.14+dfsg-1.3~deb12u4_amd64.deb", "sha", "https://xray-dev.jfrogdev.org", "deb://debian:12:libxml2", "", false, scanStatus, violations)

	assert.Equal(t, "XRAY-94620", result.Violations[0].ViolationId)

	link := result.Violations[0].Link
	assert.True(t, strings.HasPrefix(link, "https://xray-dev.jfrogdev.org/ui/scans-list/repositories/bella-test-proj-gel-local/scan-descendants/"))

	parsedUrl, err := url.Parse(link)
	assert.NoError(t, err)
	query := parsedUrl.Query()
	assert.Equal(t, "deb://debian:12:libxml2", query.Get("package_id"))
	assert.Equal(t, "bella-test-proj-gel-local/libxml2_2.9.14+dfsg-1.3~deb12u4_amd64.deb", query.Get("path"))
	assert.Equal(t, "violations", query.Get("page_type"))

	var issue scansListIssue
	assert.NoError(t, json.Unmarshal([]byte(query.Get("issue")), &issue))
	assert.Equal(t, "XRAY-94620", issue.IssueId)
	assert.Equal(t, "2096396277312823296", issue.UserIssueId)
	assert.Equal(t, "prod-watch", issue.WatcherName)
	assert.Equal(t, "security", issue.Type)
	assert.Equal(t, "deb://debian:12:libxml2:2.9.14+dfsg-1.3~deb12u4", issue.CompId)
	assert.Equal(t, "deb", issue.ComponentPackageType)
	assert.False(t, issue.IsExposuresIssue)
	assert.Equal(t, []scansListMatchedPolicy{{Policy: "no-critical-cve", Rule: "critical-cve", IsBlocking: true, BlockingMask: 1}}, issue.MatchedPolicies)
}

func TestBuildResultOrdersByBlockingThenSeverity(t *testing.T) {
	scanStatus := &services.ArtifactStatusResponse{Details: services.ArtifactDetailedStatus{
		Violations: services.ArtifactScanStatus{Status: services.ArtifactStatusDone},
	}}
	violations := []services.XrayViolation{
		{Watch: "w", Severity: "Low", Policies: []services.ViolationPolicy{{PolicyName: "low-not-blocking"}}},
		{Watch: "w", Severity: "Critical", Policies: []services.ViolationPolicy{{PolicyName: "critical-blocking", IsBlocking: true}}},
		{Watch: "w", Severity: "High", Cves: []services.CveDetails{{Id: "CVE-2020-0002"}}, Policies: []services.ViolationPolicy{{PolicyName: "high-cve-2"}}},
		{Watch: "w", Severity: "High", Cves: []services.CveDetails{{Id: "CVE-2020-0001"}}, Policies: []services.ViolationPolicy{{PolicyName: "high-cve-1"}}},
		{Watch: "w", Severity: "Medium", Cves: []services.CveDetails{{Id: "CVE-2019-0002"}}, Policies: []services.ViolationPolicy{{PolicyName: "medium-cve-2", IsBlocking: true}}},
		{Watch: "w", Severity: "Medium", Cves: []services.CveDetails{{Id: "CVE-2019-0001"}}, Policies: []services.ViolationPolicy{{PolicyName: "medium-cve-1", IsBlocking: true}}},
	}

	result := buildResult("libs-release-local", "com/acme/foo-1.2.jar", "sha", "https://acme.jfrog.io", "deb://debian:12:libxml2", "", false, scanStatus, violations)

	names := make([]string, len(result.Violations))
	for i, v := range result.Violations {
		names[i] = v.Policy
	}
	assert.Equal(t, []string{"critical-blocking", "medium-cve-1", "medium-cve-2", "high-cve-1", "high-cve-2", "low-not-blocking"}, names)
}

func TestBuildViolationUiLinkEmptyPlatformUrl(t *testing.T) {
	assert.Empty(t, buildViolationUiLink("", "repo", "path", "generic://foo", "", "", services.XrayViolation{}))
}

func TestBuildArtifactScansListLink(t *testing.T) {
	link := buildArtifactScansListLink("https://xray-dev.jfrogdev.org", "bella-test-proj-gel-local", "libxml2_2.9.14+dfsg-1.3~deb12u4_amd64.deb", "deb://debian:12:libxml2", "")

	parsedUrl, err := url.Parse(link)
	assert.NoError(t, err)
	assert.Equal(t, "/ui/scans-list/repositories/bella-test-proj-gel-local/scan-descendants/libxml2_2.9.14+dfsg-1.3~deb12u4_amd64.deb", parsedUrl.Path)

	query := parsedUrl.Query()
	assert.Equal(t, "deb://debian:12:libxml2", query.Get("package_id"))
	assert.Equal(t, "bella-test-proj-gel-local/libxml2_2.9.14+dfsg-1.3~deb12u4_amd64.deb", query.Get("path"))
	assert.Equal(t, "overview", query.Get("page_type"))
	assert.Empty(t, query.Get("version"))
	assert.Empty(t, query.Get("issue"))
}

func TestBuildArtifactScansListLinkUsesFileNameAndVersion(t *testing.T) {
	link := buildArtifactScansListLink("https://acme.jfrog.io", "libs-release-local", "com/acme/foo-1.2.jar", "gav://com.acme:foo", "1.2")

	parsedUrl, err := url.Parse(link)
	assert.NoError(t, err)
	assert.Equal(t, "/ui/scans-list/repositories/libs-release-local/scan-descendants/foo-1.2.jar", parsedUrl.Path)

	query := parsedUrl.Query()
	assert.Equal(t, "1.2", query.Get("version"))
	assert.Equal(t, "gav://com.acme:foo", query.Get("package_id"))
	assert.Equal(t, "libs-release-local/com/acme/foo-1.2.jar", query.Get("path"))
}

func TestBuildArtifactScansListLinkEmptyPlatformUrl(t *testing.T) {
	assert.Empty(t, buildArtifactScansListLink("", "repo", "path", "generic://foo", ""))
}

func TestPackageIdAndVersion(t *testing.T) {
	tests := []struct {
		name        string
		pkgType     string
		componentId string
		packageId   string
		version     string
	}{
		{name: "docker tag without scheme", pkgType: "docker", componentId: "version-test:1.2.3", packageId: "docker://version-test", version: "1.2.3"},
		{name: "docker name without version", pkgType: "docker", componentId: "version-test", packageId: "docker://version-test"},
		{name: "keeps gav scheme for gradle", pkgType: "Gradle", componentId: "gav://com.acme:foo:1.2", packageId: "gav://com.acme:foo", version: "1.2"},
		{name: "maps maven display name to gav", pkgType: "Maven", componentId: "com.acme:foo:1.2", packageId: "gav://com.acme:foo", version: "1.2"},
		{name: "maps gradle display name to gav", pkgType: "Gradle", componentId: "com.acme:foo:1.2", packageId: "gav://com.acme:foo", version: "1.2"},
		{name: "maps ivy display name to gav", pkgType: "ivy", componentId: "com.acme:foo:1.2", packageId: "gav://com.acme:foo", version: "1.2"},
		{name: "keeps deb scheme when pkg type is debian", pkgType: "Debian", componentId: "deb://debian:buster:glibc:2.28-10", packageId: "deb://debian:buster:glibc", version: "2.28-10"},
		{name: "maps debian display name to deb", pkgType: "Debian", componentId: "debian:buster:glibc:2.28-10", packageId: "deb://debian:buster:glibc", version: "2.28-10"},
		{name: "debian component id", pkgType: "deb", componentId: "deb://debian:12:libxml2:2.9.14+dfsg-1.3~deb12u4", packageId: "deb://debian:12:libxml2", version: "2.9.14+dfsg-1.3~deb12u4"},
		{name: "generic checksum stays unsplit", pkgType: "generic", componentId: "generic://sha256:abcd/analyzerManager.zip", packageId: "generic://sha256:abcd/analyzerManager.zip"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packageId, version := packageIdAndVersion(test.pkgType, test.componentId)
			assert.Equal(t, test.packageId, packageId)
			assert.Equal(t, test.version, version)
		})
	}
}

func TestBuildScansListIssueDefaultsWhenNoInfectedComponents(t *testing.T) {
	issue := buildScansListIssue(services.XrayViolation{IssueId: "XRAY-1", Type: "License"}, "")
	assert.Empty(t, issue.CompId)
	assert.Empty(t, issue.ComponentPackageType)
	assert.Equal(t, "license", issue.Type)
}

func TestBuildScansListIssueDetectsExposures(t *testing.T) {
	issue := buildScansListIssue(services.XrayViolation{ExposureDetails: &services.ExposureDetails{}}, "")
	assert.True(t, issue.IsExposuresIssue)
}

func TestBuildScansListIssueUsesArtifactAsComponentForDependency(t *testing.T) {
	issue := buildScansListIssue(services.XrayViolation{
		InfectedComponentIds: []string{"gav://com.google.guava:guava:20.0"},
	}, "docker://nginx:1.2")
	assert.Equal(t, "docker://nginx:1.2", issue.CompId)
	assert.Equal(t, "gav://com.google.guava:guava:20.0", issue.SourceCompId)
	assert.Equal(t, "docker", issue.ComponentPackageType)
}

func TestViolationState(t *testing.T) {
	assert.Equal(t, "Active", violationState(false))
	assert.Equal(t, "Ignored", violationState(true))
}

func TestBuildResultFailedScanIsUnknown(t *testing.T) {
	scanStatus := &services.ArtifactStatusResponse{Details: services.ArtifactDetailedStatus{
		Violations: services.ArtifactScanStatus{Status: services.ArtifactStatusFailed},
	}}

	result := buildResult("libs-release-local", "com/acme/foo-1.2.jar", "sha", "https://acme.jfrog.io", "gav://com.acme:foo", "1.2", false, scanStatus, nil)

	assert.Equal(t, StatusUnknown, result.DownloadStatus)
	assert.Contains(t, result.StatusReason, "failed")
}

func TestBuildResultPartialScanIsUnknown(t *testing.T) {
	scanStatus := &services.ArtifactStatusResponse{Details: services.ArtifactDetailedStatus{
		Violations: services.ArtifactScanStatus{Status: services.ArtifactStatusPartial},
	}}

	result := buildResult("libs-release-local", "com/acme/foo-1.2.jar", "sha", "https://acme.jfrog.io", "gav://com.acme:foo", "1.2", false, scanStatus, nil)

	assert.Equal(t, StatusUnknown, result.DownloadStatus)
	assert.Contains(t, result.StatusReason, "partial")
}

func TestBuildResultNotSupportedIsAllowed(t *testing.T) {
	scanStatus := &services.ArtifactStatusResponse{Details: services.ArtifactDetailedStatus{
		Violations: services.ArtifactScanStatus{Status: services.ArtifactStatusNotSupported},
	}}

	result := buildResult("libs-release-local", "com/acme/foo-1.2.jar", "sha", "https://acme.jfrog.io", "gav://com.acme:foo", "1.2", false, scanStatus, nil)

	assert.Equal(t, StatusAllowed, result.DownloadStatus)
}

func TestBuildResultChecksumMismatchIsUnknown(t *testing.T) {
	scanStatus := &services.ArtifactStatusResponse{Details: services.ArtifactDetailedStatus{
		Violations: services.ArtifactScanStatus{Status: services.ArtifactStatusDone},
	}}
	violations := []services.XrayViolation{{
		Severity: "Critical",
		Policies: []services.ViolationPolicy{{PolicyName: "no-critical-cve", IsBlocking: true}},
	}}

	result := buildResult("libs-release-local", "com/acme/foo-1.2.jar", "sha", "https://acme.jfrog.io", "gav://com.acme:foo", "1.2", true, scanStatus, violations)

	assert.Equal(t, StatusUnknown, result.DownloadStatus)
	assert.Empty(t, result.Violations)
}

func TestBuildResultPendingMentionsUnscannedBlock(t *testing.T) {
	scanStatus := &services.ArtifactStatusResponse{Details: services.ArtifactDetailedStatus{
		Violations: services.ArtifactScanStatus{Status: services.ArtifactStatusPending},
	}}

	result := buildResult("libs-release-local", "com/acme/foo-1.2.jar", "sha", "https://acme.jfrog.io", "gav://com.acme:foo", "1.2", false, scanStatus, nil)

	assert.Equal(t, StatusUnknown, result.DownloadStatus)
	assert.Contains(t, result.StatusReason, "unscanned")
}

func TestBuildResultNoViolationsIsAllowed(t *testing.T) {
	scanStatus := &services.ArtifactStatusResponse{Details: services.ArtifactDetailedStatus{
		Violations: services.ArtifactScanStatus{Status: services.ArtifactStatusDone},
	}}

	result := buildResult("libs-release-local", "com/acme/foo-1.2.jar", "sha", "https://acme.jfrog.io", "deb://debian:12:libxml2", "", false, scanStatus, nil)

	assert.Equal(t, StatusAllowed, result.DownloadStatus)
	assert.Empty(t, result.Violations)
}

func TestBuildResultFailedScanWithBlockingViolationStaysBlocked(t *testing.T) {
	scanStatus := &services.ArtifactStatusResponse{Details: services.ArtifactDetailedStatus{
		Violations: services.ArtifactScanStatus{Status: services.ArtifactStatusFailed},
	}}
	violations := []services.XrayViolation{{
		Severity: "Critical",
		Policies: []services.ViolationPolicy{{PolicyName: "no-critical-cve", IsBlocking: true}},
	}}

	result := buildResult("libs-release-local", "com/acme/foo-1.2.jar", "sha", "https://acme.jfrog.io", "gav://com.acme:foo", "1.2", false, scanStatus, violations)

	assert.Equal(t, StatusBlocked, result.DownloadStatus)
}

func TestBuildResultNonExpiredIgnoreDoesNotBlock(t *testing.T) {
	scanStatus := doneScanStatus()
	violations := []services.XrayViolation{{
		Severity:   "Critical",
		IgnoreInfo: &services.IgnoreRuleInfo{IsExpired: false},
		Policies:   []services.ViolationPolicy{{PolicyName: "no-critical-cve", IsBlocking: true}},
	}}

	result := buildResult("libs-release-local", "com/acme/foo-1.2.jar", "sha", "https://acme.jfrog.io", "gav://com.acme:foo", "1.2", false, scanStatus, violations)

	assert.Equal(t, StatusAllowed, result.DownloadStatus)
	assert.True(t, result.Violations[0].Ignored)
	assert.False(t, result.Violations[0].Blocking)
}

func TestBuildResultExpiredIgnoreStillBlocks(t *testing.T) {
	scanStatus := doneScanStatus()
	violations := []services.XrayViolation{{
		Severity:   "Critical",
		IgnoreInfo: &services.IgnoreRuleInfo{IsExpired: true},
		Policies:   []services.ViolationPolicy{{PolicyName: "no-critical-cve", IsBlocking: true}},
	}}

	result := buildResult("libs-release-local", "com/acme/foo-1.2.jar", "sha", "https://acme.jfrog.io", "gav://com.acme:foo", "1.2", false, scanStatus, violations)

	assert.Equal(t, StatusBlocked, result.DownloadStatus)
	assert.False(t, result.Violations[0].Ignored)
}

func TestBuildResultSkipNotApplicableDoesNotBlock(t *testing.T) {
	scanStatus := doneScanStatus()
	notApplicable := false
	violations := []services.XrayViolation{{
		Severity:             "High",
		ApplicabilityDetails: []services.CveApplicabilityDetails{{Status: services.NotApplicable}},
		Applicability:        []services.CveApplicability{{Applicability: &notApplicable}},
		Policies: []services.ViolationPolicy{
			{PolicyName: "skip", IsBlocking: true, SkipNotApplicable: true},
			{PolicyName: "also-skip", IsBlocking: true, SkipNotApplicable: true},
		},
	}}

	result := buildResult("libs-release-local", "com/acme/foo-1.2.jar", "sha", "https://acme.jfrog.io", "gav://com.acme:foo", "1.2", false, scanStatus, violations)

	assert.Equal(t, StatusAllowed, result.DownloadStatus)
	assert.False(t, result.Violations[0].Blocking)
	assert.False(t, result.Violations[1].Blocking)
}

func TestBuildResultSkipNotApplicableStillBlocksWhenAnotherPolicyDoesNotSkip(t *testing.T) {
	scanStatus := doneScanStatus()
	violations := []services.XrayViolation{{
		Severity:             "High",
		ApplicabilityDetails: []services.CveApplicabilityDetails{{Status: services.NotApplicable}},
		Policies: []services.ViolationPolicy{
			{PolicyName: "skip", IsBlocking: true, SkipNotApplicable: true},
			{PolicyName: "enforce", IsBlocking: true},
		},
	}}

	result := buildResult("libs-release-local", "com/acme/foo-1.2.jar", "sha", "https://acme.jfrog.io", "gav://com.acme:foo", "1.2", false, scanStatus, violations)

	assert.Equal(t, StatusBlocked, result.DownloadStatus)
	blockingByPolicy := map[string]bool{}
	for _, row := range result.Violations {
		blockingByPolicy[row.Policy] = row.Blocking
	}
	assert.False(t, blockingByPolicy["skip"])
	assert.True(t, blockingByPolicy["enforce"])
}

func TestBuildResultUsesIssueIdAndFallsBackToViolationId(t *testing.T) {
	scanStatus := doneScanStatus()
	withIssue := buildResult("repo", "a.jar", "", "https://acme.jfrog.io", "generic://a.jar", "", false, scanStatus, []services.XrayViolation{{
		IssueId:  "XRAY-1",
		Id:       "99",
		Policies: []services.ViolationPolicy{{PolicyName: "p"}},
	}})
	assert.Equal(t, "XRAY-1", withIssue.Violations[0].ViolationId)

	withRecordOnly := buildResult("repo", "a.jar", "", "https://acme.jfrog.io", "generic://a.jar", "", false, scanStatus, []services.XrayViolation{{
		Id:       "99",
		Policies: []services.ViolationPolicy{{PolicyName: "p"}},
	}})
	assert.Equal(t, "99", withRecordOnly.Violations[0].ViolationId)
}

func TestArtifactSummaryPathsIncludeProjectBeforeDefault(t *testing.T) {
	cmd := NewDownloadStatusCommand().SetRepoAndPathCandidates("libs-release-local", nil)
	assert.Equal(t, []string{"libs-release-local/com/acme/foo.jar", "default/libs-release-local/com/acme/foo.jar"}, cmd.artifactSummaryPaths("com/acme/foo.jar"))

	cmd.SetProject("team-a")
	assert.Equal(t, []string{
		"libs-release-local/com/acme/foo.jar",
		"team-a/libs-release-local/com/acme/foo.jar",
		"default/libs-release-local/com/acme/foo.jar",
	}, cmd.artifactSummaryPaths("com/acme/foo.jar"))
}

func TestIsArtifactNotFound(t *testing.T) {
	assert.True(t, isArtifactNotFound(&errorutils.HttpResponseError{StatusCode: http.StatusNotFound}))
	assert.False(t, isArtifactNotFound(&errorutils.HttpResponseError{StatusCode: http.StatusForbidden}))
	assert.False(t, isArtifactNotFound(errors.New("connection reset")))
}

func doneScanStatus() *services.ArtifactStatusResponse {
	return &services.ArtifactStatusResponse{Details: services.ArtifactDetailedStatus{
		Violations: services.ArtifactScanStatus{Status: services.ArtifactStatusDone},
	}}
}
