package utils

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSameRegistryHost(t *testing.T) {
	testCases := []struct {
		name       string
		configured string
		discovered string
		expected   bool
	}{
		{name: "same host, different path and case", configured: "https://a.example.com/artifactory/", discovered: "https://A.example.com/artifactory/api/npm/r/", expected: true},
		{name: "explicit default https port equals no port", configured: "https://a.example.com/artifactory/", discovered: "https://a.example.com:443/artifactory/api/npm/r/", expected: true},
		{name: "explicit default port on the configured side", configured: "https://a.example.com:443/", discovered: "https://a.example.com/artifactory/", expected: true},
		{name: "explicit default http port equals no port", configured: "http://a.example.com:80/", discovered: "http://a.example.com/", expected: true},
		{name: "scheme mismatch", configured: "https://a.example.com/artifactory/", discovered: "http://a.example.com/artifactory/", expected: false},
		{name: "host mismatch", configured: "https://a.example.com/artifactory/", discovered: "https://b.example.com/artifactory/", expected: false},
		{name: "non-default port mismatch", configured: "https://a.example.com/", discovered: "https://a.example.com:8443/", expected: false},
		{name: "empty configured url", configured: "", discovered: "https://b.example.com/", expected: false},
		{name: "dotted capital I look-alike", configured: "https://internal.example.com/", discovered: "https://\u0130nternal.example.com/", expected: false},
		{name: "dotted capital I look-alike on the configured side", configured: "https://\u0130nternal.example.com/", discovered: "https://internal.example.com/", expected: false},
		{name: "kelvin sign look-alike", configured: "https://keep.example.com/", discovered: "https://\u212aeep.example.com/", expected: false},
		{name: "long s look-alike", configured: "https://secure.example.com/", discovered: "https://\u017fecure.example.com/", expected: false},
		{name: "identical non-ASCII host still matches itself", configured: "https://b\u00fccher.example.com/", discovered: "https://b\u00fccher.example.com/x", expected: true},
		{name: "ASCII upper case host and scheme", configured: "https://a.example.com/", discovered: "HTTPS://A.EXAMPLE.COM:443/x", expected: true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, SameRegistryHost(tc.configured, tc.discovered))
		})
	}
}

func TestRedactUrlUserinfo(t *testing.T) {
	testCases := []struct {
		name     string
		raw      string
		expected string
	}{
		{name: "username-only token", raw: "https://secrettoken@a.example.com/artifactory/api/npm/r/", expected: "https://a.example.com/artifactory/api/npm/r/"},
		{name: "user and password", raw: (&url.URL{Scheme: "https", User: url.UserPassword("user", "pw"), Host: "a.example.com", Path: "/x"}).String(), expected: "https://a.example.com/x"},
		{name: "no userinfo is unchanged", raw: "https://a.example.com/x", expected: "https://a.example.com/x"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, RedactUrlUserinfo(tc.raw))
		})
	}
}
