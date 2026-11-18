package utils

import (
	"net"
	"net/url"
)

// SameRegistryHost reports whether both URLs share the same scheme and host:port (paths ignored, default ports 80/443 normalized).
func SameRegistryHost(configuredUrl, discoveredUrl string) bool {
	configured, err := url.Parse(configuredUrl)
	if err != nil || configured.Host == "" {
		return false
	}
	discovered, err := url.Parse(discoveredUrl)
	if err != nil || discovered.Host == "" {
		return false
	}
	return asciiLower(configured.Scheme) == asciiLower(discovered.Scheme) && effectiveHostPort(configured) == effectiveHostPort(discovered)
}

// effectiveHostPort returns host:port with the scheme's default port filled in when absent.
func effectiveHostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch asciiLower(u.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return net.JoinHostPort(asciiLower(u.Hostname()), port)
}

// asciiLower lowercases ASCII letters only. Unicode lowering or folding (e.g. İ to i, the Kelvin sign to k) would make a
// look-alike host equal to the configured one, while Node and Yarn resolve it through IDNA to a different host.
func asciiLower(s string) string {
	lowered := []byte(s)
	for i, c := range lowered {
		if 'A' <= c && c <= 'Z' {
			lowered[i] = c + ('a' - 'A')
		}
	}
	return string(lowered)
}

// RedactUrlUserinfo drops any userinfo (including username-only tokens) so credentials never reach logs or errors.
func RedactUrlUserinfo(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<unparsable url>"
	}
	u.User = nil
	return u.String()
}
