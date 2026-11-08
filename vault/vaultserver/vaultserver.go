package vaultserver

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ErrInsecureServer is a server URL that would carry secrets unencrypted.
var ErrInsecureServer = errors.New("vault: the password hash and tokens would travel unencrypted")

// Server is where an account lives: an official cloud by its name, or
// a self-hosted server (or Vaultwarden) by its base URL, https unless
// it is on this machine. The zero Server is none.
type Server struct{ s string }

// The official clouds, by the names ParseServer takes.
const (
	CloudUS = "bitwarden.com"
	CloudEU = "bitwarden.eu"
)

// ParseServer reads a server setting: CloudUS, CloudEU, or an http(s)
// base URL without a query or fragment. A URL CheckTransport refuses is
// an error matching ErrInsecureServer.
func ParseServer(s string) (Server, error) {
	if s == CloudUS || s == CloudEU {
		return Server{s}, nil
	}
	u, err := url.Parse(strings.TrimRight(s, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return Server{}, fmt.Errorf("vault: server %q is neither %s, %s nor an http(s) base URL", s, CloudUS, CloudEU)
	}
	if err := CheckTransport(u); err != nil {
		return Server{}, err
	}
	return Server{u.String()}, nil
}

// CheckTransport refuses a URL that would carry the password hash and
// the tokens unencrypted off this machine: http to anything but loopback.
func CheckTransport(u *url.URL) error {
	if u.Scheme != "http" || isLoopback(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("%w: %s; use https://, as http:// is only for a server on this machine", ErrInsecureServer, u.Redacted())
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// String is the cloud's name or the base URL.
func (s Server) String() string { return s.s }

// Redacted is String with any password in the URL masked, for a log.
func (s Server) Redacted() string {
	u, err := url.Parse(s.s)
	if err != nil {
		return "the configured server"
	}
	return u.Redacted()
}

// MarshalText implements encoding.TextMarshaler.
func (s Server) MarshalText() ([]byte, error) { return []byte(s.s), nil }

// UnmarshalText implements encoding.TextUnmarshaler, refusing what
// ParseServer refuses.
func (s *Server) UnmarshalText(b []byte) error {
	parsed, err := ParseServer(string(b))
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}
