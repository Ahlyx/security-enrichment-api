package validators

import (
	"net"
	"regexp"
	"strings"
)

var (
	domainRe = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	md5Re    = regexp.MustCompile(`^[a-f0-9]{32}$`)
	sha1Re   = regexp.MustCompile(`^[a-f0-9]{40}$`)
	sha256Re = regexp.MustCompile(`^[a-f0-9]{64}$`)

	// Additional reserved/bogon ranges not covered by Go stdlib IsPrivate().
	bogonCIDRs = mustParseCIDRs([]string{
		"100.64.0.0/10",    // Shared address space (RFC 6598)
		"192.0.0.0/24",     // IETF protocol assignments
		"192.0.2.0/24",     // TEST-NET-1 (RFC 5737)
		"198.18.0.0/15",    // Benchmarking (RFC 2544)
		"198.51.100.0/24",  // TEST-NET-2
		"203.0.113.0/24",   // TEST-NET-3
		"240.0.0.0/4",      // Reserved for future use
		"255.255.255.255/32", // Broadcast
	})
)

func mustParseCIDRs(cidrs []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, cidr := range cidrs {
		_, n, err := net.ParseCIDR(cidr)
		if err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}

func IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func IsPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsPrivate()
}

// IsBogonIP mirrors Python's is_bogon_ip: private, loopback, link-local,
// multicast, reserved, unspecified, and additional RFC special-purpose ranges.
func IsBogonIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() ||
		parsed.IsLinkLocalMulticast() || parsed.IsMulticast() || parsed.IsUnspecified() {
		return true
	}
	for _, network := range bogonCIDRs {
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

func IsValidDomain(domain string) bool {
	return domainRe.MatchString(domain)
}

func IsValidHash(hash string) bool {
	h := strings.ToLower(strings.TrimSpace(hash))
	return md5Re.MatchString(h) || sha1Re.MatchString(h) || sha256Re.MatchString(h)
}

// GetHashType returns "md5", "sha1", "sha256", or empty string.
func GetHashType(hash string) string {
	h := strings.ToLower(strings.TrimSpace(hash))
	switch {
	case md5Re.MatchString(h):
		return "md5"
	case sha1Re.MatchString(h):
		return "sha1"
	case sha256Re.MatchString(h):
		return "sha256"
	}
	return ""
}

func IsValidURL(u string) bool {
	return strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")
}
