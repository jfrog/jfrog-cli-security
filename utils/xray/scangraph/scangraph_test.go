package scangraph

import (
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	coreXray "github.com/jfrog/jfrog-cli-core/v2/utils/xray"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/assert"
)

func TestUseXscGraphScan(t *testing.T) {
	tests := []struct {
		name   string
		params *services.XrayGraphScanParams
		want   bool
	}{
		{name: "nil params", params: nil, want: false},
		{
			name: "dependency with analytics uses XSC",
			params: &services.XrayGraphScanParams{
				ScanType:    services.Dependency,
				XscVersion:  "1.16.0",
				MultiScanId: "msi",
			},
			want: true,
		},
		{
			name: "binary never uses XSC even with analytics ids",
			params: &services.XrayGraphScanParams{
				ScanType:    services.Binary,
				XscVersion:  "1.16.0",
				MultiScanId: "msi",
			},
			want: false,
		},
		{
			name: "dependency without multi scan id stays on Xray",
			params: &services.XrayGraphScanParams{
				ScanType:   services.Dependency,
				XscVersion: "1.16.0",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, useXscGraphScan(tt.params))
		})
	}
}

func TestDisableXscForBinaryScan(t *testing.T) {
	binary := &services.XrayGraphScanParams{ScanType: services.Binary, XscVersion: "1.16.0", MultiScanId: "msi"}
	disableXscForBinaryScan(binary)
	assert.Empty(t, binary.XscVersion)
	assert.Empty(t, binary.MultiScanId)

	dep := &services.XrayGraphScanParams{ScanType: services.Dependency, XscVersion: "1.16.0", MultiScanId: "msi"}
	disableXscForBinaryScan(dep)
	assert.Equal(t, "1.16.0", dep.XscVersion)
	assert.Equal(t, "msi", dep.MultiScanId)
}

func TestBinaryScanWithEmptyGraphTargetsXrayEndpoint(t *testing.T) {
	var postPath, postBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			postPath = r.URL.Path
			body, err := io.ReadAll(r.Body)
			assert.NoError(t, err)
			postBody = string(body)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"scan_id":"scan-1"}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	params := NewScanGraphParams().
		SetServerDetails(&config.ServerDetails{XrayUrl: server.URL + "/"}).
		SetXrayGraphScanParams(&services.XrayGraphScanParams{
			ScanType:    services.Binary,
			XrayVersion: "3.120.0",
			XscVersion:  "1.16.0",
			MultiScanId: "msi-from-analytics",
			BinaryGraph: &xrayUtils.BinaryGraphNode{Id: "npm://left-pad:1.3.0", Sha256: "abc"},
		})
	xrayManager, err := coreXray.CreateXrayServiceManager(params.ServerDetails())
	assert.NoError(t, err)

	_, err = RunScanGraphAndGetResults(params, xrayManager)
	assert.NoError(t, err)
	assert.Contains(t, postPath, "api/v1/scan/graph")
	assert.NotContains(t, postPath, "sca/scan/graph")
	assert.Contains(t, postBody, "npm://left-pad:1.3.0")
}

func TestScanGraphParamsCloneDoesNotShareMutableGraph(t *testing.T) {
	original := NewScanGraphParams().
		SetXrayGraphScanParams(&services.XrayGraphScanParams{
			ProjectKey: "proj",
			Technology: "npm",
		}).
		SetTechnology(techutils.Npm)
	cloned := original.Clone()

	cloned.XrayGraphScanParams().DependenciesGraph = &xrayUtils.GraphNode{Id: "cloned-root"}
	cloned.XrayGraphScanParams().Technology = techutils.Yarn.String()
	cloned.SetTechnology(techutils.Yarn)

	assert.Nil(t, original.XrayGraphScanParams().DependenciesGraph)
	assert.Equal(t, techutils.Npm, original.Technology())
	assert.Equal(t, "npm", original.XrayGraphScanParams().Technology)
	assert.Equal(t, "proj", cloned.XrayGraphScanParams().ProjectKey)
	assert.Equal(t, "cloned-root", cloned.XrayGraphScanParams().DependenciesGraph.Id)
}

func TestFilterResultIfNeeded(t *testing.T) {
	// Define test cases
	tests := []struct {
		name       string
		scanResult services.ScanResponse
		params     ScanGraphParams
		expected   services.ScanResponse
	}{
		{
			name:       "Should not filter",
			scanResult: services.ScanResponse{},
			params:     ScanGraphParams{},
			expected:   services.ScanResponse{},
		},
		{
			name: "No filter level specified",
			scanResult: services.ScanResponse{
				Violations: []services.Violation{
					{Severity: "Unknown"},
					{Severity: "Information"},
					{Severity: "Low"},
					{Severity: "Medium"},
					{Severity: "High"},
					{Severity: "Critical"},
				},
				Vulnerabilities: []services.Vulnerability{
					{Severity: "Unknown"},
					{Severity: "Information"},
					{Severity: "Low"},
					{Severity: "Medium"},
					{Severity: "High"},
					{Severity: "Critical"},
				},
			},
			params: ScanGraphParams{
				severityLevel: 0,
			},
			expected: services.ScanResponse{
				Violations: []services.Violation{
					{Severity: "Unknown"},
					{Severity: "Information"},
					{Severity: "Low"},
					{Severity: "Medium"},
					{Severity: "High"},
					{Severity: "Critical"},
				},
				Vulnerabilities: []services.Vulnerability{
					{Severity: "Unknown"},
					{Severity: "Information"},
					{Severity: "Low"},
					{Severity: "Medium"},
					{Severity: "High"},
					{Severity: "Critical"},
				},
			},
		},
		{
			name: "Filter violations and vulnerabilities by high severity",
			scanResult: services.ScanResponse{
				Violations: []services.Violation{
					{Severity: "Unknown"},
					{Severity: "Information"},
					{Severity: "Low"},
					{Severity: "Medium"},
					{Severity: "High"},
					{Severity: "Critical"},
				},
				Vulnerabilities: []services.Vulnerability{
					{Severity: "Unknown"},
					{Severity: "Information"},
					{Severity: "Low"},
					{Severity: "Medium"},
					{Severity: "High"},
					{Severity: "Critical"},
				},
			},
			params: ScanGraphParams{
				severityLevel: 30,
			},
			expected: services.ScanResponse{
				Violations: []services.Violation{
					{Severity: "High"},
					{Severity: "Critical"},
				},
				Vulnerabilities: []services.Vulnerability{
					{Severity: "High"},
					{Severity: "Critical"},
				},
			},
		},
	}

	// Run test cases
	for i := range tests {
		t.Run(tests[i].name, func(t *testing.T) {
			// Call the function with the input parameters
			actual := filterResultIfNeeded(&tests[i].scanResult, &tests[i].params)
			// Check that the function returned the expected result
			assert.True(t, reflect.DeepEqual(*actual, tests[i].expected))
		})
	}
}

func TestGetFixableComponents(t *testing.T) {
	// create test cases
	testCases := []struct {
		name        string
		components  map[string]services.Component
		expectedMap map[string]services.Component
	}{
		{
			name: "Returns an empty map when all components have no fixed versions",
			components: map[string]services.Component{
				"vuln1": {
					FixedVersions: []string{},
				},
				"vuln2": {
					FixedVersions: []string{},
				},
			},
			expectedMap: map[string]services.Component{},
		},
		{
			name: "Returns a filtered map with only components that have fixed versions",
			components: map[string]services.Component{
				"vuln1": {
					FixedVersions: []string{},
				},
				"vuln2": {
					FixedVersions: []string{"1.0.0"},
				},
				"vuln3": {
					FixedVersions: []string{"2.0.0", "3.0.0"},
				},
				"vuln4": {
					FixedVersions: []string{},
				},
			},
			expectedMap: map[string]services.Component{
				"vuln2": {
					FixedVersions: []string{"1.0.0"},
				},
				"vuln3": {
					FixedVersions: []string{"2.0.0", "3.0.0"},
				},
			},
		},
	}

	// run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualMap := getFixableComponents(tc.components)
			assert.Equal(t, len(tc.expectedMap), len(actualMap))
			for k, v := range tc.expectedMap {
				if v.FixedVersions == nil {
					assert.True(t, actualMap[k].FixedVersions == nil)
				} else {
					assert.Equal(t, len(actualMap[k].FixedVersions), len(v.FixedVersions))
				}
			}
		})
	}
}
