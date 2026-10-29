package vault

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stubbedev/lys-lib/dbustest"
	"github.com/stubbedev/lys-lib/dbusx"
	dbus "github.com/stubbedev/lys-lib/third_party/godbus"
)

// fakeHost records what the daemon asks and answers what the test set.
type fakeHost struct {
	mu       sync.Mutex
	status   Status
	items    []Item
	itemsErr error
	value    Value
	fieldErr error
	asked    []string
	logins   []LoginRequest
	apiKeys  []APIKeyRequest
	loginErr error
	network  NetworkLogin
}

// with runs fn under the host's lock: the daemon's calls arrive on
// goroutines of their own.
func (h *fakeHost) with(fn func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	fn()
}

func (h *fakeHost) record(s string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.asked = append(h.asked, s)
}

func (h *fakeHost) Status() Status {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.status
}

func (h *fakeHost) Items() ([]Item, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.items, h.itemsErr
}

func (h *fakeHost) Field(id string, f Field, password string) (Value, error) {
	h.record(fmt.Sprintf("field %s %d %s", id, f, password))
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.value, h.fieldErr
}

func (h *fakeHost) Login(_ context.Context, r LoginRequest) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.logins = append(h.logins, r)
	return h.loginErr
}

func (h *fakeHost) SendLoginEmail(_ context.Context, r LoginRequest) error {
	h.record("email " + r.Email)
	return nil
}

func (h *fakeHost) LoginAPIKey(_ context.Context, r APIKeyRequest) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.apiKeys = append(h.apiKeys, r)
	return nil
}

func (h *fakeHost) Unlock(_ context.Context, password string) error {
	h.record("unlock " + password)
	if password != "master" {
		return fmt.Errorf("bitwarden: %w", ErrWrongPassword)
	}
	return nil
}

func (h *fakeHost) Lock()         { h.record("lock") }
func (h *fakeHost) Logout() error { h.record("logout"); return nil }

func (h *fakeHost) Sync(context.Context) error {
	h.record("sync")
	return &ServerError{Status: 503, Message: "maintenance"}
}

func (h *fakeHost) NetworkLogin(folder, name string) (NetworkLogin, bool) {
	if folder != "Networks" || name != "Home" {
		return NetworkLogin{}, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.network, true
}

// testBus is a private bus whose connections close with the test.
type testBus struct {
	t       *testing.T
	address string
}

func (b testBus) conn() *dbus.Conn {
	c, err := dbus.Connect(b.address)
	if err != nil {
		b.t.Fatal(err)
	}
	b.t.Cleanup(func() { _ = c.Close() })
	return c
}

// serveOn exports a daemon over host on a private bus and returns it
// with a client on another connection of the same bus, and the bus.
func serveOn(t *testing.T, host Host) (*Daemon, *Client, *dbus.Conn, testBus) {
	t.Helper()
	return serveAs(t, host, uint32(os.Getuid()))
}

// serveAs is serveOn with the daemon serving the user uid.
func serveAs(t *testing.T, host Host, uid uint32) (*Daemon, *Client, *dbus.Conn, testBus) {
	t.Helper()
	bus := testBus{t, dbustest.Start(t).Address}
	d := NewDaemon(context.Background(), host)
	d.uid = uid
	release, err := d.Export(bus.conn())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	other := bus.conn()
	return d, NewClient(other), other, bus
}

func serve(t *testing.T, host Host) (*Daemon, *Client, *dbus.Conn) {
	t.Helper()
	d, c, conn, _ := serveOn(t, host)
	return d, c, conn
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

// The status crosses the bus whole, its error typed again on the
// client's side.
func TestStatusRoundTrip(t *testing.T) {
	last := time.Unix(1_700_000_000, 0)
	wrong := fmt.Errorf("bitwarden: unlock: %w", ErrWrongPassword)
	for name, c := range map[string]struct {
		err  error
		same func(error) bool
	}{
		"none": {nil, func(got error) bool { return got == nil }},
		"wrong password": {wrong, func(got error) bool {
			return errors.Is(got, ErrWrongPassword) && got.Error() == wrong.Error()
		}},
		"server": {&ServerError{Status: 429, Message: "slow down"}, func(got error) bool {
			se, ok := errors.AsType[*ServerError](got)
			return ok && *se == ServerError{Status: 429, Message: "slow down"} && se.Retryable()
		}},
		"second factor": {&TwoFactorRequiredError{Providers: []TwoFactorProvider{TwoFactorEmail}}, func(got error) bool {
			tf, ok := errors.AsType[*TwoFactorRequiredError](got)
			return ok && slices.Equal(tf.Providers, []TwoFactorProvider{TwoFactorEmail})
		}},
	} {
		host := &fakeHost{status: Status{State: StateUnlocked, Email: "ada@example.com", Syncing: true, LastSync: last, Items: 3, Err: c.err}}
		_, client, _ := serve(t, host)
		got, err := client.Status(ctx(t))
		if err != nil {
			t.Fatal(err)
		}
		if got.State != StateUnlocked || got.Email != "ada@example.com" || !got.Syncing || !got.LastSync.Equal(last) || got.Items != 3 {
			t.Errorf("%s: status = %+v", name, got)
		}
		if !c.same(got.Err) {
			t.Errorf("%s: the error came back as %#v", name, got.Err)
		}
	}
}

// A status of a state the contract does not define is refused.
func TestStatusRefusesAnUnknownState(t *testing.T) {
	if _, err := fromWire(wireStatus{State: 7}); err == nil {
		t.Error("state 7 accepted")
	}
}

// Items list the open vault as the host does; a locked vault is
// ErrLocked, and an item of a type or field the contract does not
// define is refused.
func TestItems(t *testing.T) {
	mail := Item{ID: "a", Type: ItemLogin, Name: "Mail", Username: "ada", URIs: []string{"https://mail.example.com"}, Fields: []Field{FieldPassword, FieldUsername}}
	host := &fakeHost{items: []Item{mail}}
	_, c, _ := serve(t, host)
	items, err := c.Items(ctx(t))
	if err != nil || len(items) != 1 || items[0].Name != "Mail" || !slices.Equal(items[0].Fields, mail.Fields) || items[0].URIs[0] != mail.URIs[0] {
		t.Fatalf("items = %+v, %v", items, err)
	}
	host.with(func() { host.items, host.itemsErr = nil, ErrLocked })
	if _, err := c.Items(ctx(t)); !errors.Is(err, ErrLocked) {
		t.Errorf("a locked vault = %v", err)
	}
	host.with(func() { host.items, host.itemsErr = []Item{{ID: "x", Type: 9}}, nil })
	if _, err := c.Items(ctx(t)); err == nil {
		t.Error("an item of type 9 was accepted")
	}
	host.with(func() { host.items = []Item{{ID: "x", Type: ItemLogin, Fields: []Field{42}}} })
	if _, err := c.Items(ctx(t)); err == nil {
		t.Error("an item offering field 42 was accepted")
	}
}

// A field crosses with its expiry, the master password reaches the
// host, and the host's refusal comes back typed; a field the contract
// does not define never reaches the host.
func TestField(t *testing.T) {
	expires := time.Unix(1_700_000_030, 0)
	host := &fakeHost{value: Value{Text: "123456", Expires: expires}}
	_, c, conn := serve(t, host)
	v, err := c.Field(ctx(t), "a", FieldTOTP, "master")
	if err != nil || v.Text != "123456" || !v.Expires.Equal(expires) {
		t.Errorf("code = %+v, %v", v, err)
	}
	host.with(func() { host.value = Value{Text: "hunter2"} })
	if v, err := c.Field(ctx(t), "a", FieldPassword, ""); err != nil || !v.Expires.IsZero() {
		t.Errorf("password = %+v, %v", v, err)
	}
	host.with(func() { host.fieldErr = fmt.Errorf("%w: Bank", ErrRepromptRequired) })
	if _, err := c.Field(ctx(t), "b", FieldPassword, ""); !errors.Is(err, ErrRepromptRequired) || !strings.Contains(err.Error(), "Bank") {
		t.Errorf("reprompt = %v", err)
	}
	if err := conn.Object(ServiceName, ServicePath).CallWithContext(ctx(t), iface+".Field", 0, "a", uint32(99), "").Err; err == nil {
		t.Error("field 99 was accepted")
	}
	host.with(func() {
		if !slices.Equal(host.asked, []string{"field a 2 master", "field a 1 ", "field b 1 "}) {
			t.Errorf("the host was asked %q", host.asked)
		}
	})
}

// A login crosses with its server, second factor and device code; the
// server asking for a factor comes back with its providers. A server
// setting the contract does not take never reaches the host.
func TestLogin(t *testing.T) {
	host := &fakeHost{loginErr: &TwoFactorRequiredError{Providers: []TwoFactorProvider{TwoFactorAuthenticator, TwoFactorEmail}}}
	_, c, conn := serve(t, host)
	eu, _ := ParseServer(CloudEU)
	err := c.Login(ctx(t), LoginRequest{Server: eu, Email: "ada@example.com", Password: "pw"})
	var tf *TwoFactorRequiredError
	if !errors.As(err, &tf) || !slices.Equal(tf.Providers, []TwoFactorProvider{TwoFactorAuthenticator, TwoFactorEmail}) {
		t.Fatalf("login = %v", err)
	}
	host.with(func() { host.loginErr = nil })
	req := LoginRequest{Server: eu, Email: "ada@example.com", Password: "pw", TwoFactor: &TwoFactor{Provider: TwoFactorEmail, Code: "123456"}, NewDeviceOTP: "999"}
	if err := c.Login(ctx(t), req); err != nil {
		t.Fatal(err)
	}
	var got LoginRequest
	host.with(func() { got = host.logins[1] })
	if got.Server != eu || got.Email != req.Email || got.Password != "pw" || *got.TwoFactor != *req.TwoFactor || got.NewDeviceOTP != "999" {
		t.Errorf("host got %+v", got)
	}
	host.with(func() {
		if host.logins[0].TwoFactor != nil {
			t.Error("a login without a factor reached the host with one")
		}
	})
	if err := c.LoginAPIKey(ctx(t), APIKeyRequest{Server: eu, Email: "ada@example.com", ClientID: "user.x", Secret: "s", Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	host.with(func() {
		if host.apiKeys[0].ClientID != "user.x" || host.apiKeys[0].Server != eu {
			t.Errorf("API key login reached the host as %+v", host.apiKeys)
		}
	})
	bad := wireLogin{Server: "ftp://nope", Email: "ada@example.com"}
	if err := conn.Object(ServiceName, ServicePath).CallWithContext(ctx(t), iface+".Login", 0, bad).Err; err == nil {
		t.Error("a bad server was accepted")
	}
	host.with(func() {
		if len(host.logins) != 2 {
			t.Errorf("a bad server reached the host: %d logins", len(host.logins))
		}
	})
}

// Unlock, lock, logout and sync reach the host, their failures typed.
func TestLifecycle(t *testing.T) {
	host := &fakeHost{}
	_, c, _ := serve(t, host)
	if err := c.Unlock(ctx(t), "nope"); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("wrong password = %v", err)
	}
	if err := c.Unlock(ctx(t), "master"); err != nil {
		t.Error(err)
	}
	var se *ServerError
	if err := c.Sync(ctx(t)); !errors.As(err, &se) || se.Status != 503 || se.Message != "maintenance" {
		t.Errorf("sync = %#v", err)
	}
	if err := c.Lock(ctx(t)); err != nil {
		t.Error(err)
	}
	if err := c.Logout(ctx(t)); err != nil {
		t.Error(err)
	}
	host.with(func() {
		if want := []string{"unlock nope", "unlock master", "sync", "lock", "logout"}; !slices.Equal(host.asked, want) {
			t.Errorf("asked %q, want %q", host.asked, want)
		}
	})
}

// Locking a vault nobody serves finds nothing to lock and starts
// nothing; another call there fails.
func TestLockWithoutAVault(t *testing.T) {
	bus := testBus{t, dbustest.Start(t).Address}
	c := NewClient(bus.conn())
	if err := c.Lock(ctx(t)); err != nil {
		t.Errorf("lock without a vault = %v", err)
	}
	if _, err := c.Status(ctx(t)); err == nil {
		t.Error("a status came from no vault")
	}
}

// The network login crosses with its fields; none is false.
func TestNetworkLogin(t *testing.T) {
	host := &fakeHost{network: NetworkLogin{Username: "ann", Password: "hunter22", Fields: map[string]string{"pin": "1234"}}}
	_, c, _ := serve(t, host)
	l, ok, err := c.NetworkLogin(ctx(t), "Networks", "Home")
	if err != nil || !ok || l.Username != "ann" || l.Password != "hunter22" || l.Fields["pin"] != "1234" {
		t.Errorf("login = %+v %v %v", l, ok, err)
	}
	if l, ok, err := c.NetworkLogin(ctx(t), "Networks", "Office"); err != nil || ok || l.Password != "" {
		t.Errorf("no login = %+v %v %v", l, ok, err)
	}
}

// A caller running as another user is refused before the host is
// asked anything.
func TestAnotherUserIsRefused(t *testing.T) {
	host := &fakeHost{value: Value{Text: "hunter2"}}
	_, c, _, _ := serveAs(t, host, uint32(os.Getuid())+1)
	if _, err := c.Field(ctx(t), "a", FieldPassword, ""); !errors.Is(err, ErrAccessDenied) {
		t.Errorf("another user's Field = %v", err)
	}
	if _, err := c.Status(ctx(t)); !errors.Is(err, ErrAccessDenied) {
		t.Errorf("another user's Status = %v", err)
	}
	if _, _, err := c.NetworkLogin(ctx(t), "Networks", "Home"); !errors.Is(err, ErrAccessDenied) {
		t.Errorf("another user's NetworkLogin = %v", err)
	}
	host.with(func() {
		if len(host.asked) != 0 {
			t.Errorf("the host was asked %q", host.asked)
		}
	})
}

// Watch delivers the daemon's Changed and SyncFailed signals and
// ignores the same signals from anyone else; introspection lists both.
func TestWatch(t *testing.T) {
	host := &fakeHost{status: Status{State: StateLocked, Email: "ada@example.com"}}
	d, c, conn, bus := serveOn(t, host)
	statuses := make(chan Status, 4)
	failures := make(chan error, 4)
	if err := c.Watch(ctx(t), Watcher{Changed: func(s Status) { statuses <- s }, SyncFailed: func(err error) { failures <- err }}); err != nil {
		t.Fatal(err)
	}
	// Another watcher on the client's connection matches the interface
	// from any sender, so the impostor's signal reaches the connection.
	if err := conn.AddMatchSignal(dbus.WithMatchInterface(iface)); err != nil {
		t.Fatal(err)
	}
	if err := changed.Emit(bus.conn(), ServicePath, toWire(Status{State: StateUnlocked})); err != nil {
		t.Fatal(err)
	}
	if err := d.Changed(); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-statuses:
		if s.State != StateLocked || s.Email != "ada@example.com" {
			t.Errorf("changed = %+v, want the daemon's, not the impostor's", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no Changed")
	}
	if err := d.SyncFailed(fmt.Errorf("refresh: %w", ErrLoginRequired)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-failures:
		if !errors.Is(err, ErrLoginRequired) {
			t.Errorf("sync failed with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no SyncFailed")
	}
	var xml string
	if err := conn.Object(ServiceName, ServicePath).Call("org.freedesktop.DBus.Introspectable.Introspect", 0).Store(&xml); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{`<signal name="Changed">`, `<signal name="SyncFailed">`, `<method name="Field">`} {
		if !strings.Contains(xml, name) {
			t.Errorf("introspection lacks %s", name)
		}
	}
}

// A second daemon on the same bus finds the name taken and leaves
// nothing exported.
func TestExportRefusesATakenName(t *testing.T) {
	_, _, other, bus := serveOn(t, &fakeHost{})
	second := bus.conn()
	if _, err := NewDaemon(context.Background(), &fakeHost{}).Export(second); !errors.Is(err, dbusx.ErrNameTaken) {
		t.Errorf("second export = %v", err)
	}
	var st wireStatus
	if err := other.Object(second.Names()[0], ServicePath).Call(iface+".Status", 0).Store(&st); err == nil {
		t.Errorf("the second daemon still answers Status: %+v", st)
	}
}

// The clouds parse by name, a self-hosted base URL to its canonical
// form; anything else is refused, and so is unmarshalling it.
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

// Search matches every word against the name, username, URIs and
// folder, ignoring case.
func TestItemMatch(t *testing.T) {
	it := Item{Name: "Mail", Username: "ada@example.com", URIs: []string{"https://mail.example.com"}, Folder: "Work"}
	for q, want := range map[string]bool{"": true, "mail": true, "MAIL work": true, "ada example": true, "bank": false, "mail bank": false} {
		if got := it.Match(q); got != want {
			t.Errorf("Match(%q) = %v", q, got)
		}
	}
}

// Usernames and emails are not secrets; every other field is.
func TestFieldSecret(t *testing.T) {
	for f := FieldUsername; f <= FieldNotes; f++ {
		if want := f != FieldUsername && f != FieldEmail; f.Secret() != want {
			t.Errorf("field %d secret = %v", f, f.Secret())
		}
	}
}
