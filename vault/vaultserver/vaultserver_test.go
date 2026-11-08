package vaultserver

import (
	"errors"
	"strings"
	"testing"
)

// The clouds parse by name, a self-hosted base URL to its canonical
// form; anything else is refused, and so is unmarshalling it.
func TestParseServerRefusesPlainHTTPOffThisMachine(t *testing.T) {
	for _, ok := range []string{
		"http://localhost:8080", "http://LOCALHOST", "HTTP://localhost/vault",
		"http://127.0.0.1:8000", "http://127.1.2.3", "http://[::1]:8000", "https://vault.example.com",
	} {
		if _, err := ParseServer(ok); err != nil {
			t.Errorf("ParseServer(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://vault.example.com", "http://192.168.1.2:8080", "http://10.0.0.1",
		"http://localhost.example.com", "http://127.0.0.1.example.com", "http://[::ffff:8.8.8.8]",
		"http://2130706433", "http://user:hunter2@vault.example.com",
	} {
		_, err := ParseServer(bad)
		if !errors.Is(err, ErrInsecureServer) {
			t.Errorf("ParseServer(%q) = %v, want ErrInsecureServer", bad, err)
			continue
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("the error shows the URL's password: %v", err)
		}
	}
	var s Server
	if err := s.UnmarshalText([]byte("http://vault.example.com")); !errors.Is(err, ErrInsecureServer) {
		t.Errorf("UnmarshalText = %v, want ErrInsecureServer", err)
	}
}

func TestParseServer(t *testing.T) {
	if s, err := ParseServer(CloudEU); err != nil || s.String() != CloudEU {
		t.Errorf("EU cloud = %v, %v", s, err)
	}
	if s, err := ParseServer("https://vault.example.com/"); err != nil || s.String() != "https://vault.example.com" {
		t.Errorf("self-hosted = %v, %v", s, err)
	}
	for _, bad := range []string{"vault.example.com", "ftp://x", "", "https://x/?a=b", "bitwarden.org"} {
		if _, err := ParseServer(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
		var s Server
		if err := s.UnmarshalText([]byte(bad)); err == nil {
			t.Errorf("%q unmarshalled", bad)
		}
	}
}

func TestServerRedactedHidesAPassword(t *testing.T) {
	s, err := ParseServer("https://user:hunter2@vault.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Redacted(); strings.Contains(got, "hunter2") || !strings.Contains(got, "vault.example.com") {
		t.Errorf("Redacted = %q", got)
	}
	cloud, _ := ParseServer(CloudUS)
	if got := cloud.Redacted(); got != CloudUS {
		t.Errorf("Redacted = %q, want %q", got, CloudUS)
	}
}
