package utils

import (
	"net"
	"net/url"
	"strings"
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
	return strings.EqualFold(configured.Scheme, discovered.Scheme) && strings.EqualFold(effectiveHostPort(configured), effectiveHostPort(discovered))
}

// effectiveHostPort returns host:port with the scheme's default port filled in when absent.
func effectiveHostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return net.JoinHostPort(strings.ToLower(u.Hostname()), port)
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
