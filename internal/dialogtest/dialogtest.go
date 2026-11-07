// Package dialogtest is the shell's dialog host as a test sees it: it serves
// dev.stubbe.lys.PortalDialogs1 on the test's bus, records each password and
// access dialog, and answers them from the test's script.
package dialogtest

import (
	"sync"
	"testing"

	"github.com/stubbedev/lys-lib/portaldialogs"
	dbus "github.com/stubbedev/lys-lib/third_party/godbus"
)

// Host records the dialogs it is asked for and answers them with Password and
// Access, which dismiss every dialog while nil.
type Host struct {
	mu        sync.Mutex
	passwords []portaldialogs.PasswordRequest
	accesses  []portaldialogs.AccessRequest
	// Password answers a password dialog.
	Password func(portaldialogs.PasswordRequest) (bool, string, []portaldialogs.Selection)
	// Access answers an access dialog.
	Access func(portaldialogs.AccessRequest) (bool, []portaldialogs.Selection)
}

// Serve serves h on conn until the test ends.
func Serve(t testing.TB, conn *dbus.Conn, h *Host) {
	t.Helper()
	release, err := portaldialogs.NewDaemon(daemon{h}).Export(conn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
}

// Asked is every password and access dialog shown so far, in order.
func (h *Host) Asked() ([]portaldialogs.PasswordRequest, []portaldialogs.AccessRequest) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]portaldialogs.PasswordRequest(nil), h.passwords...), append([]portaldialogs.AccessRequest(nil), h.accesses...)
}

// daemon is h as portaldialogs.Host, apart from the answer fields' names.
type daemon struct{ h *Host }

func (d daemon) Password(_ portaldialogs.Caller, r portaldialogs.PasswordRequest) (bool, string, []portaldialogs.Selection) {
	h := d.h
	h.mu.Lock()
	h.passwords = append(h.passwords, r)
	answer := h.Password
	h.mu.Unlock()
	if answer == nil {
		return false, "", nil
	}
	return answer(r)
}

func (d daemon) Access(_ portaldialogs.Caller, r portaldialogs.AccessRequest) (bool, []portaldialogs.Selection) {
	h := d.h
	h.mu.Lock()
	h.accesses = append(h.accesses, r)
	answer := h.Access
	h.mu.Unlock()
	if answer == nil {
		return false, nil
	}
	return answer(r)
}

func (daemon) Account(portaldialogs.Caller, string, portaldialogs.AccountInfo) (bool, portaldialogs.AccountInfo) {
	return false, portaldialogs.AccountInfo{}
}

func (daemon) ConfirmWallpaper(portaldialogs.Caller, string) bool { return false }

func (daemon) ChooseApplication(portaldialogs.Caller, portaldialogs.ChooserRequest) string {
	return ""
}

func (daemon) UpdateChoices(string, []string) bool { return false }

func (daemon) ChooseDevices(portaldialogs.Caller, []portaldialogs.Device) (bool, []string) {
	return false, nil
}

func (daemon) ConfirmInstall(portaldialogs.Caller, portaldialogs.LauncherRequest) (bool, string) {
	return false, ""
}

func (daemon) Authenticate(portaldialogs.Caller, portaldialogs.AuthRequest) portaldialogs.AuthReply {
	return portaldialogs.AuthCancel{}
}

func (daemon) ShowAuthentication(portaldialogs.Caller, portaldialogs.AuthRequest) {}

func (daemon) Dismiss(string) {}
