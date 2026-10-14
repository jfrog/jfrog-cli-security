package catalog

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	catalogServices "github.com/jfrog/jfrog-client-go/catalog/services"
	xrayutils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestServerDetails(serverUrl string) *config.ServerDetails {
	return &config.ServerDetails{Url: serverUrl + "/"}
}

func testBom() *cyclonedx.BOM {
	return &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{
			{Name: "lodash", Version: "4.17.21", PackageURL: "pkg:npm/lodash@4.17.21"},
		},
	}
}

func TestGetIndirectCvePaths_EmptyCves_ReturnsNilWithoutError(t *testing.T) {
	result, err := GetIndirectCvePaths(newTestServerDetails("http://unused.invalid"), "", nil, testBom())

	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestGetIndirectCvePaths_NilBom_ReturnsNilWithoutError(t *testing.T) {
	result, err := GetIndirectCvePaths(newTestServerDetails("http://unused.invalid"), "", []string{"CVE-2024-1234"}, nil)

	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestGetIndirectCvePaths_ManagerCreationFails_ReturnsWrappedError(t *testing.T) {
	serverDetails := newTestServerDetails("http://unused.invalid")
	// A client cert path that doesn't exist on disk makes the underlying HTTP client
	// creation fail deterministically, without needing a real network call.
	serverDetails.ClientCertPath = "/path/does/not/exist/cert.pem"
	serverDetails.ClientCertKeyPath = "/path/does/not/exist/key.pem"

	result, err := GetIndirectCvePaths(serverDetails, "", []string{"CVE-2024-1234"}, testBom())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create catalog service manager")
	assert.Nil(t, result)
}

func TestGetIndirectCvePaths_ServerError_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	result, err := GetIndirectCvePaths(newTestServerDetails(server.URL), "", []string{"CVE-2024-1234"}, testBom())

	require.Error(t, err)
	assert.Nil(t, result)
}

func TestGetIndirectCvePaths_ServerReturnsMalformedJson_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	}))
	defer server.Close()

	result, err := GetIndirectCvePaths(newTestServerDetails(server.URL), "", []string{"CVE-2024-1234"}, testBom())

	require.Error(t, err)
	assert.Nil(t, result)
}

// TestToCatalogPackageVersionKeys_FromRealPurls drives each case through a real purl string via
// cdxutils.ExtractPackageVersionKeys, the same path GetIndirectCvePaths uses, rather than hand-building
// PackageVersionKey values. A hand-built Namespace/Name split can't catch a wrong or missing fold: joinPackageName
// is a plain concatenation, so any split of the same full string reassembles to the same result (e.g. splitting
// "golang.org/x/sys" as namespace "golang.org"/name "x/sys", or as namespace "golang.org/x"/name "sys" - which is
// what the real purl library actually returns - both rejoin to the identical string). Only exercising the real
// extractor proves the split/fold pipeline is correct end-to-end.
func TestToCatalogPackageVersionKeys_FromRealPurls(t *testing.T) {
	testCases := []struct {
		name     string
		purl     string
		expected xrayutils.PackageVersionKey
	}{
		{
			name: "namespaced type outside the switch keeps its namespace folded in",
			purl: "pkg:cocoapods/AppAuth/Core@1.7.5",
			expected: xrayutils.PackageVersionKey{
				Type: "cocoapods", Name: "AppAuth/Core", Namespace: catalogNamespacePublic, Version: "1.7.5", Ecosystem: xrayutils.GenericEcosystem,
			},
		},
		{
			name: "go v2+ module path is reconstructed regardless of where the real purl splits namespace/name",
			purl: "pkg:golang/github.com/foo/bar/v2@2.3.4",
			expected: xrayutils.PackageVersionKey{
				Type: "golang", Name: "github.com/foo/bar/v2", Namespace: catalogNamespacePublic, Version: "v2.3.4", Ecosystem: xrayutils.GenericEcosystem,
			},
		},
		{
			name: "go pseudo-version that already has v is not double-prefixed",
			purl: "pkg:golang/golang.org/x/sys@v0.0.0-20200116001909-b77594299b42",
			expected: xrayutils.PackageVersionKey{
				Type: "golang", Name: "golang.org/x/sys", Namespace: catalogNamespacePublic, Version: "v0.0.0-20200116001909-b77594299b42", Ecosystem: xrayutils.GenericEcosystem,
			},
		},
		{
			name: "go +incompatible version round-trips untouched",
			purl: "pkg:golang/github.com/old/pkg@v3.0.0+incompatible",
			expected: xrayutils.PackageVersionKey{
				Type: "golang", Name: "github.com/old/pkg", Namespace: catalogNamespacePublic, Version: "v3.0.0+incompatible", Ecosystem: xrayutils.GenericEcosystem,
			},
		},
		{
			name: "scoped npm package decodes the percent-encoded @ and keeps its single-segment namespace",
			purl: "pkg:npm/%40protobufjs/aspromise@1.1.2",
			expected: xrayutils.PackageVersionKey{
				Type: "npm", Name: "@protobufjs/aspromise", Namespace: catalogNamespacePublic, Version: "1.1.2", Ecosystem: xrayutils.GenericEcosystem,
			},
		},
		{
			name: "unscoped npm package has no namespace to fold",
			purl: "pkg:npm/lodash@4.17.21",
			expected: xrayutils.PackageVersionKey{
				Type: "npm", Name: "lodash", Namespace: catalogNamespacePublic, Version: "4.17.21", Ecosystem: xrayutils.GenericEcosystem,
			},
		},
		{
			name: "pypi package has no namespace to fold",
			purl: "pkg:pypi/requests@2.28.0",
			expected: xrayutils.PackageVersionKey{
				Type: "pypi", Name: "requests", Namespace: catalogNamespacePublic, Version: "2.28.0", Ecosystem: xrayutils.GenericEcosystem,
			},
		},
		{
			name: "maven groupId:artifactId is rejoined with : instead of the purl's /",
			purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
			expected: xrayutils.PackageVersionKey{
				Type: "maven", Name: "org.apache.logging.log4j:log4j-core", Namespace: catalogNamespacePublic, Version: "2.14.1", Ecosystem: xrayutils.GenericEcosystem,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bom := &cyclonedx.BOM{Components: &[]cyclonedx.Component{{PackageURL: tc.purl}}}
			extracted := cdxutils.ExtractPackageVersionKeys(bom)
			require.Len(t, extracted, 1)

			got := toCatalogPackageVersionKeys(extracted)

			require.Len(t, got, 1)
			assert.Equal(t, tc.expected, got[0])
		})
	}
}

func TestGetIndirectCvePaths_Success_SendsExpectedRequestAndParsesResponse(t *testing.T) {
	var gotBody struct {
		Cves     []string                      `json:"cves"`
		Packages []xrayutils.PackageVersionKey `json:"packages"`
	}
	var gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]catalogServices.IndirectContextualResponse{
			"CVE-2024-1234": {
				PackageVersionKey: xrayutils.PackageVersionKey{Type: "npm", Name: "lodash", Version: "4.17.21", Ecosystem: xrayutils.GenericEcosystem},
				Functions:         []string{"merge"},
			},
		})
	}))
	defer server.Close()

	result, err := GetIndirectCvePaths(newTestServerDetails(server.URL), "myproj", []string{"CVE-2024-1234"}, testBom())

	require.NoError(t, err)
	assert.Equal(t, []string{"CVE-2024-1234"}, gotBody.Cves)
	assert.Equal(t, []xrayutils.PackageVersionKey{{Type: "npm", Name: "lodash", Namespace: "public", Version: "4.17.21", Ecosystem: xrayutils.GenericEcosystem}}, gotBody.Packages)
	assert.Equal(t, "projectKey=myproj", gotQuery)
	require.Contains(t, result, "CVE-2024-1234")
	assert.Equal(t, "lodash", result["CVE-2024-1234"].Name)
	assert.Equal(t, []string{"merge"}, result["CVE-2024-1234"].Functions)
}
