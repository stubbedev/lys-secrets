package main

import (
	"sync"
	"testing"

	"github.com/stubbedev/lys-lib/portaldialogs"
	dbus "github.com/stubbedev/lys-lib/third_party/godbus"
)

// fakeHost is the shell's dialog host on the test's bus: it records each
// password and access dialog and answers it from a script.
type fakeHost struct {
	mu        sync.Mutex
	passwords []portaldialogs.PasswordRequest
	accesses  []portaldialogs.AccessRequest
	password  func(portaldialogs.PasswordRequest) (bool, string, []portaldialogs.Selection)
	access    func(portaldialogs.AccessRequest) (bool, []portaldialogs.Selection)
}

func serveHost(t *testing.T, conn *dbus.Conn, h *fakeHost) {
	t.Helper()
	release, err := portaldialogs.NewDaemon(h).Export(conn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
}

func (h *fakeHost) asked() ([]portaldialogs.PasswordRequest, []portaldialogs.AccessRequest) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]portaldialogs.PasswordRequest(nil), h.passwords...), append([]portaldialogs.AccessRequest(nil), h.accesses...)
}

func (h *fakeHost) Password(_ portaldialogs.Caller, r portaldialogs.PasswordRequest) (bool, string, []portaldialogs.Selection) {
	h.mu.Lock()
	h.passwords = append(h.passwords, r)
	answer := h.password
	h.mu.Unlock()
	if answer == nil {
		return false, "", nil
	}
	return answer(r)
}

func (h *fakeHost) Access(_ portaldialogs.Caller, r portaldialogs.AccessRequest) (bool, []portaldialogs.Selection) {
	h.mu.Lock()
	h.accesses = append(h.accesses, r)
	answer := h.access
	h.mu.Unlock()
	if answer == nil {
		return false, nil
	}
	return answer(r)
}

func (*fakeHost) Account(portaldialogs.Caller, string, portaldialogs.AccountInfo) (bool, portaldialogs.AccountInfo) {
	return false, portaldialogs.AccountInfo{}
}

func (*fakeHost) ConfirmWallpaper(portaldialogs.Caller, string) bool { return false }

func (*fakeHost) ChooseApplication(portaldialogs.Caller, portaldialogs.ChooserRequest) string {
	return ""
}

func (*fakeHost) UpdateChoices(string, []string) bool { return false }

func (*fakeHost) ChooseDevices(portaldialogs.Caller, []portaldialogs.Device) (bool, []string) {
	return false, nil
}

func (*fakeHost) ConfirmInstall(portaldialogs.Caller, portaldialogs.LauncherRequest) (bool, string) {
	return false, ""
}

func (*fakeHost) Authenticate(portaldialogs.Caller, portaldialogs.AuthRequest) portaldialogs.AuthReply {
	return portaldialogs.AuthCancel{}
}

func (*fakeHost) ShowAuthentication(portaldialogs.Caller, portaldialogs.AuthRequest) {}

func (*fakeHost) Dismiss(string) {}
