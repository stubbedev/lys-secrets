package pinentry

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeUI answers every passphrase dialog with pin, remembering it when
// remember is set, and every question with yes; err fails each dialog.
type fakeUI struct {
	pin      string
	remember bool
	yes      bool
	err      error
	cancel   bool
	block    bool
	pins     []Request
	confirms []Request
}

func (f *fakeUI) GetPin(ctx context.Context, r Request) ([]byte, bool, bool, error) {
	f.pins = append(f.pins, r)
	if f.block {
		<-ctx.Done()
		return nil, false, false, ctx.Err()
	}
	if f.err != nil {
		return nil, false, false, f.err
	}
	if f.cancel {
		return nil, false, false, nil
	}
	return []byte(f.pin), f.remember, true, nil
}

func (f *fakeUI) Confirm(_ context.Context, r Request, _ bool) (bool, error) {
	f.confirms = append(f.confirms, r)
	return f.yes, f.err
}

type fakeCache struct {
	mu      sync.Mutex
	pins    map[string]string
	lookups int
}

func (c *fakeCache) Lookup(_ context.Context, keyinfo string) ([]byte, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lookups++
	pin, ok := c.pins[keyinfo]
	return []byte(pin), ok, nil
}

func (c *fakeCache) Store(_ context.Context, keyinfo string, pin []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pins[keyinfo] = string(pin)
	return nil
}

func (c *fakeCache) Clear(_ context.Context, keyinfo string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.pins, keyinfo)
	return nil
}

// converse runs Serve over the commands and returns its answer lines.
func converse(t *testing.T, ui UI, cache Cache, commands string) []string {
	t.Helper()
	var out strings.Builder
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := Serve(ctx, strings.NewReader(commands), &out, ui, cache); err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
}

// answers splits the lines after the greeting into one answer per command:
// its status and data lines, up to and including its OK or ERR.
func answers(t *testing.T, lines []string) [][]string {
	t.Helper()
	if !strings.HasPrefix(lines[0], "OK Pleased to meet you") {
		t.Fatalf("the greeting is %q", lines[0])
	}
	var out [][]string
	var cur []string
	for _, l := range lines[1:] {
		cur = append(cur, l)
		if l == "OK" || strings.HasPrefix(l, "OK ") || strings.HasPrefix(l, "ERR ") {
			out = append(out, cur)
			cur = nil
		}
	}
	if len(cur) != 0 {
		t.Fatalf("an answer has no end: %q", cur)
	}
	return out
}

func commandsOf(t *testing.T, name string) (string, []string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var cmds []string
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		cmds = append(cmds, sc.Text())
	}
	return string(data), cmds
}

// A real gpg-agent session, recorded from gpg 2.4 with a scripted pinentry,
// is answered command by command.
func TestRecordedGpgAgentSessionsAreAnswered(t *testing.T) {
	for _, name := range []string{"gpg-agent-sign.in", "gpg-agent-retry.in", "gpg-agent-new.in", "gpg-agent-confirm.in"} {
		t.Run(name, func(t *testing.T) {
			data, cmds := commandsOf(t, name)
			ui := &fakeUI{pin: "hunter2", yes: true}
			got := answers(t, converse(t, ui, &fakeCache{pins: map[string]string{}}, data))
			if len(got) != len(cmds) {
				t.Fatalf("%d answers to %d commands: %q", len(got), len(cmds), got)
			}
			for i, cmd := range cmds {
				a := got[i]
				end := a[len(a)-1]
				switch verb, arg, _ := strings.Cut(cmd, " "); verb {
				case "GETINFO":
					if len(a) != 2 || !strings.HasPrefix(a[0], "D ") || end != "OK" {
						t.Errorf("%s = %q", cmd, a)
					}
					if arg == "flavor" && a[0] != "D lys" {
						t.Errorf("%s = %q", cmd, a)
					}
				case "GETPIN":
					if a[len(a)-2] != "D hunter2" || end != "OK" {
						t.Errorf("%s = %q", cmd, a)
					}
				case "BYE":
					if end != "OK closing connection" {
						t.Errorf("%s = %q", cmd, a)
					}
				default:
					if len(a) != 1 || end != "OK" {
						t.Errorf("%s = %q", cmd, a)
					}
				}
			}
			for _, r := range ui.pins {
				if r.Prompt != "Passphrase:" {
					t.Errorf("a passphrase dialog asked %+v", r)
				}
			}
		})
	}
}

func TestTheRecordedSessionsSetUpTheirDialogs(t *testing.T) {
	data, _ := commandsOf(t, "gpg-agent-retry.in")
	ui := &fakeUI{pin: "hunter2"}
	converse(t, ui, &fakeCache{pins: map[string]string{}}, data)
	if len(ui.pins) != 2 || ui.pins[0].Error != "" || ui.pins[1].Error != "Bad Passphrase (try 2 of 3)" {
		t.Fatalf("asked %+v, want a second dialog saying why", ui.pins)
	}
	if !strings.Contains(ui.pins[0].Description, "\n\"Test <t@example.org>\"\n") || !ui.pins[0].Remember {
		t.Errorf("the dialog showed %+v, want the decoded description and the offer to remember", ui.pins[0])
	}

	data, _ = commandsOf(t, "gpg-agent-new.in")
	ui = &fakeUI{pin: "hunter2"}
	lines := converse(t, ui, &fakeCache{pins: map[string]string{}}, data)
	if !slices.Contains(lines, pinRepeated) || len(ui.pins) != 1 || !ui.pins[0].Repeat || ui.pins[0].Remember {
		t.Errorf("a new passphrase asked %+v and answered %q", ui.pins, lines)
	}

	data, _ = commandsOf(t, "gpg-agent-confirm.in")
	ui = &fakeUI{}
	got := answers(t, converse(t, ui, nil, data))
	if len(ui.confirms) != 1 || ui.confirms[0].OK != "Take this one anyway" || ui.confirms[0].Cancel != "Enter new passphrase" {
		t.Errorf("CONFIRM asked %+v", ui.confirms)
	}
	if !slices.ContainsFunc(got, func(a []string) bool { return strings.HasPrefix(a[0], "ERR 83886179 ") }) {
		t.Errorf("a refused CONFIRM answered %q", got)
	}
}

const cached = "OPTION allow-external-password-cache\nSETKEYINFO n/ABCD\nGETPIN\n"

func TestARememberedPassphraseNeedsNoDialog(t *testing.T) {
	cache := &fakeCache{pins: map[string]string{}}
	ui := &fakeUI{pin: "p%ss\nword", remember: true}
	lines := converse(t, ui, cache, cached)
	if !slices.Contains(lines, "D p%25ss%0Aword") || cache.pins["n/ABCD"] != "p%ss\nword" {
		t.Fatalf("answered %q, cached %q", lines, cache.pins)
	}
	ui = &fakeUI{}
	lines = converse(t, ui, cache, cached)
	if len(ui.pins) != 0 || !slices.Contains(lines, passwordFromCache) || !slices.Contains(lines, "D p%25ss%0Aword") {
		t.Errorf("a cached passphrase asked %d dialogs and answered %q", len(ui.pins), lines)
	}
	ui = &fakeUI{pin: "new"}
	converse(t, ui, cache, "OPTION allow-external-password-cache\nSETKEYINFO n/ABCD\nSETERROR Bad Passphrase\nGETPIN\n")
	if len(ui.pins) != 1 {
		t.Errorf("after a wrong cached passphrase %d dialogs asked", len(ui.pins))
	}
	if _, kept := cache.pins["n/ABCD"]; kept {
		t.Error("a passphrase the user did not ask to remember left the old one cached")
	}
	ui = &fakeUI{pin: "x", remember: true}
	converse(t, ui, cache, "SETKEYINFO n/ABCD\nGETPIN\n")
	if len(cache.pins) != 0 || ui.pins[0].Remember {
		t.Errorf("without allow-external-password-cache: cached %q, offered %v", cache.pins, ui.pins[0].Remember)
	}
}

func TestWithoutADialogHostTheAgentHearsNoPinentry(t *testing.T) {
	ui := &fakeUI{err: ErrNoDialogHost}
	lines := converse(t, ui, nil, "SETDESC x\nGETPIN\nGETPIN\nBYE\n")
	if got := lines[len(lines)-1]; !strings.HasPrefix(got, "ERR 83886165 ") || len(ui.pins) != 1 {
		t.Errorf("answered %q after %d dialogs, want GPG_ERR_NO_PIN_ENTRY and an end", lines, len(ui.pins))
	}
}

func TestCancelTimeoutAndUnknownCommands(t *testing.T) {
	lines := converse(t, &fakeUI{cancel: true}, nil, "GETPIN\n")
	if !strings.HasPrefix(lines[1], "ERR 83886179 ") {
		t.Errorf("a cancelled dialog answered %q", lines)
	}
	lines = converse(t, &fakeUI{block: true}, nil, "SETTIMEOUT 1\nGETPIN\n")
	if !strings.HasPrefix(lines[2], "ERR 83886142 ") {
		t.Errorf("a timed out dialog answered %q", lines)
	}
	lines = converse(t, &fakeUI{err: errors.New("bus gone")}, nil, "GETPIN\nFROB\nGETINFO nothing\nSETTIMEOUT x\n# comment\n\nNOP\n")
	want := []string{"ERR 83886081 ", "ERR 83886355 ", "ERR 83886360 ", "ERR 83886360 ", "OK"}
	for i, w := range want {
		if !strings.HasPrefix(lines[i+1], w) {
			t.Errorf("answer %d = %q, want %q", i, lines[i+1], w)
		}
	}
	lines = converse(t, &fakeUI{}, nil, strings.Repeat("x", maxLine+10)+"\nNOP\n")
	if !strings.HasPrefix(lines[1], "ERR 83886343 ") || lines[2] != "OK" {
		t.Errorf("an overlong line answered %q", lines)
	}
}

func TestLongDataIsSplitAndEscaped(t *testing.T) {
	pin := strings.Repeat("%", 600)
	lines := converse(t, &fakeUI{pin: pin}, nil, "GETPIN\n")
	var joined strings.Builder
	for _, l := range lines[1 : len(lines)-1] {
		if len(l)+1 > maxLine || !strings.HasPrefix(l, "D ") {
			t.Fatalf("a data line of %d bytes: %.20q", len(l), l)
		}
		joined.WriteString(unescape(strings.TrimPrefix(l, "D ")))
	}
	if joined.String() != pin || len(lines) < 4 {
		t.Errorf("%d lines carry %d bytes", len(lines), joined.Len())
	}
}
