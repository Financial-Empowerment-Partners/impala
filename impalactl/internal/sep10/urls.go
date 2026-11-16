package sep10

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var homeDomainPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[1-9][0-9]{0,4})?$`)

// IsValidHomeDomain reports whether d is a lowercase host name or IPv4
// address, optionally with :port, short enough that "<d> auth" fits a
// manage-data key (impala-lib Sep10Urls.isValidHomeDomain).
func IsValidHomeDomain(d string) bool {
	return len(d) <= 59 && homeDomainPattern.MatchString(d)
}

// HomeDomainOf is the default home domain for a bridge endpoint: its
// host[:port], lowercased, the port only when the URL states one.
func HomeDomainOf(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid endpoint %q", endpoint)
	}
	return strings.ToLower(u.Host), nil
}

// CheckWebAuthEndpoint parses a WEB_AUTH_ENDPOINT: an absolute http(s) URL
// with a host and no user info, query or fragment. It returns the URL and
// its web_auth_domain (the lowercased host, plus :port when the URL states a
// port), which a challenge's web_auth_domain operation must carry.
func CheckWebAuthEndpoint(endpoint string) (*url.URL, string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, "", errors.New("WEB_AUTH_ENDPOINT is not a URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return nil, "", errors.New("WEB_AUTH_ENDPOINT must be http(s)")
	}
	if u.Hostname() == "" {
		return nil, "", errors.New("WEB_AUTH_ENDPOINT has no host")
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, "", errors.New("WEB_AUTH_ENDPOINT must not carry user info, a query or a fragment")
	}
	domain := strings.ToLower(u.Hostname())
	if p := u.Port(); p != "" {
		domain += ":" + p
	}
	if len(domain) > 64 {
		return nil, "", errors.New("WEB_AUTH_ENDPOINT host longer than 64 characters")
	}
	return u, domain, nil
}
