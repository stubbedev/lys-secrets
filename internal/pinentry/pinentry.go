// Package pinentry speaks GnuPG's pinentry protocol, Assuan over a
// process's standard input and output, for gpg-agent: it asks for
// passphrases and confirmations through a UI, and, where gpg-agent allows
// an external password cache, keeps passphrases in one under the
// org.gnupg.Passphrase schema pinentry-gnome3 uses.
package pinentry

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// Schema is the xdg:schema of a cached passphrase; its keygrip attribute is
// the key info gpg-agent names the key by, as pinentry-gnome3 stores it.
const Schema = "org.gnupg.Passphrase"

// ErrNoDialogHost is a UI with no dialog host to ask through: gpg-agent
// hears GPG_ERR_NO_PIN_ENTRY and the pinentry ends.
var ErrNoDialogHost = errors.New("pinentry: no dialog host to ask through")

// Request is what a dialog shows, as gpg-agent set it.
type Request struct {
	Title, Description, Prompt string
	// Error says why the previous passphrase was refused, "" for none.
	Error string
	// OK and Cancel label the buttons, "" for the UI's own, as gpg-agent
	// wrote them: with GnuPG's mnemonic underscores.
	OK, Cancel string
	// Repeat asks for the passphrase twice, a new one.
	Repeat bool
	// Remember offers to keep the passphrase in the cache.
	Remember bool
}

// UI asks the user.
type UI interface {
	// GetPin asks for a passphrase; ok is false when the user cancelled,
	// and remember says they asked to keep it.
	GetPin(ctx context.Context, r Request) (pin []byte, remember, ok bool, err error)
	// Confirm asks a yes or no question; oneButton only tells something.
	Confirm(ctx context.Context, r Request, oneButton bool) (bool, error)
}

// Cache keeps passphrases by gpg-agent's key info.
type Cache interface {
	Lookup(ctx context.Context, keyinfo string) (pin []byte, found bool, err error)
	Store(ctx context.Context, keyinfo string, pin []byte) error
	Clear(ctx context.Context, keyinfo string) error
}

// gpg-error codes, from the pinentry source (5).
const (
	sourcePinentry    = 5 << 24
	errGeneral        = sourcePinentry | 1
	errTimeout        = sourcePinentry | 62
	errNoPinEntry     = sourcePinentry | 85
	errCanceled       = sourcePinentry | 99
	errUnknownCmd     = sourcePinentry | 275
	errParameter      = sourcePinentry | 280
	errLineTooLong    = sourcePinentry | 263
	maxLine           = 1000
	dataLinePayload   = maxLine - len("D \n") - 2
	flavor            = "lys"
	protocolVersion   = "1.3.1"
	pinRepeated       = "S PIN_REPEATED"
	passwordFromCache = "S PASSWORD_FROM_CACHE"
)

// session is what gpg-agent set since the last RESET.
type session struct {
	req        Request
	keyinfo    string
	allowCache bool
	timeout    time.Duration
}

// Serve answers gpg-agent on r and w until it says BYE, the input ends, or
// a dialog finds no dialog host. cache may be nil.
func Serve(ctx context.Context, r io.Reader, w io.Writer, ui UI, cache Cache) error {
	s := &server{in: bufio.NewReaderSize(r, maxLine+1), out: w, ui: ui, cache: cache}
	return s.serve(ctx)
}

type server struct {
	in    *bufio.Reader
	out   io.Writer
	ui    UI
	cache Cache
	s     session
}

// errEnd ends the conversation once its answer is written.
var errEnd = errors.New("pinentry: the conversation ended")

func (sv *server) serve(ctx context.Context) error {
	if err := sv.line("OK Pleased to meet you, process " + strconv.Itoa(os.Getpid())); err != nil {
		return err
	}
	for {
		line, err := sv.in.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = sv.in.ReadSlice('\n')
			}
			if werr := sv.fail(errLineTooLong, "Line too long"); werr != nil {
				return werr
			}
			continue
		}
		if errors.Is(err, io.EOF) && len(line) == 0 {
			return nil
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("pinentry: read a command: %w", err)
		}
		text := strings.TrimRight(string(line), "\r\n")
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		cmd, arg, _ := strings.Cut(text, " ")
		switch err := sv.command(ctx, strings.ToUpper(cmd), arg); {
		case errors.Is(err, errEnd):
			return nil
		case err != nil:
			return err
		}
	}
}

func (sv *server) command(ctx context.Context, cmd, arg string) error {
	s := &sv.s
	set := func(field *string) error {
		*field = unescape(arg)
		return sv.ok()
	}
	switch cmd {
	case "BYE":
		if err := sv.line("OK closing connection"); err != nil {
			return err
		}
		return errEnd
	case "NOP", "SETQUALITYBAR", "SETQUALITYBAR_TT", "SETGENPIN", "SETGENPIN_TT", "SETREPEATOK", "SETREPEATERROR", "SETNOTOK", "SETFORMATTED-PASSPHRASE", "SETCONSTRAINTS", "END":
		return sv.ok()
	case "RESET":
		sv.s = session{}
		return sv.ok()
	case "OPTION":
		name, _, _ := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		name, _, _ = strings.Cut(name, " ")
		if name == "allow-external-password-cache" {
			s.allowCache = true
		}
		return sv.ok()
	case "GETINFO":
		return sv.info(arg)
	case "SETDESC":
		return set(&s.req.Description)
	case "SETPROMPT":
		return set(&s.req.Prompt)
	case "SETTITLE":
		return set(&s.req.Title)
	case "SETERROR":
		return set(&s.req.Error)
	case "SETOK":
		return set(&s.req.OK)
	case "SETCANCEL":
		return set(&s.req.Cancel)
	case "SETREPEAT":
		s.req.Repeat = true
		return sv.ok()
	case "SETKEYINFO":
		s.keyinfo = ""
		if arg != "--clear" {
			s.keyinfo = unescape(arg)
		}
		return sv.ok()
	case "SETTIMEOUT":
		n, err := strconv.ParseUint(strings.TrimSpace(arg), 10, 32)
		if err != nil {
			return sv.fail(errParameter, "IPC parameter error")
		}
		s.timeout = time.Duration(n) * time.Second
		return sv.ok()
	case "CLEARPASSPHRASE":
		if sv.cache != nil && arg != "" {
			if err := sv.cache.Clear(ctx, unescape(arg)); err != nil {
				fmt.Fprintf(os.Stderr, "pinentry: clear the cached passphrase of %s: %v\n", arg, err)
			}
		}
		return sv.ok()
	case "GETPIN":
		return sv.getPin(ctx)
	case "CONFIRM":
		return sv.confirm(ctx, strings.TrimSpace(arg) == "--one-button")
	case "MESSAGE":
		return sv.confirm(ctx, true)
	default:
		return sv.fail(errUnknownCmd, "Unknown IPC command")
	}
}

func (sv *server) info(what string) error {
	var value string
	switch strings.TrimSpace(what) {
	case "flavor":
		value = flavor
	case "version":
		value = protocolVersion
	case "pid":
		value = strconv.Itoa(os.Getpid())
	case "ttyinfo":
		value = "- - - - 0/0 -"
	default:
		return sv.fail(errParameter, "IPC parameter error")
	}
	if err := sv.data([]byte(value)); err != nil {
		return err
	}
	return sv.ok()
}

// dialog is the context a dialog runs under: SETTIMEOUT's bound, if any.
func (sv *server) dialog(ctx context.Context) (context.Context, context.CancelFunc) {
	if sv.s.timeout > 0 {
		return context.WithTimeout(ctx, sv.s.timeout)
	}
	return context.WithCancel(ctx)
}

// cacheable reports whether gpg-agent lets this passphrase be cached.
func (sv *server) cacheable() bool {
	return sv.cache != nil && sv.s.allowCache && sv.s.keyinfo != ""
}

func (sv *server) getPin(ctx context.Context) error {
	s := &sv.s
	defer func() { s.req.Error = "" }()
	if sv.cacheable() && s.req.Error == "" {
		pin, found, err := sv.cache.Lookup(ctx, s.keyinfo)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pinentry: look up the cached passphrase of %s: %v\n", s.keyinfo, err)
		}
		if found {
			defer clear(pin)
			if err := sv.line(passwordFromCache); err != nil {
				return err
			}
			if err := sv.data(pin); err != nil {
				return err
			}
			return sv.ok()
		}
	}
	req := s.req
	req.Remember = sv.cacheable()
	dctx, cancel := sv.dialog(ctx)
	defer cancel()
	pin, remember, ok, err := sv.ui.GetPin(dctx, req)
	defer clear(pin)
	if err != nil {
		return sv.dialogFailed(dctx, err)
	}
	if !ok {
		return sv.fail(errCanceled, "Operation cancelled")
	}
	if req.Repeat {
		if err := sv.line(pinRepeated); err != nil {
			return err
		}
	}
	if err := sv.data(pin); err != nil {
		return err
	}
	if req.Remember {
		sv.keep(ctx, pin, remember)
	}
	return sv.ok()
}

// keep stores pin in the cache when the user asked, and clears what the cache
// held otherwise.
func (sv *server) keep(ctx context.Context, pin []byte, remember bool) {
	keyinfo := sv.s.keyinfo
	if remember {
		if err := sv.cache.Store(ctx, keyinfo, pin); err != nil {
			fmt.Fprintf(os.Stderr, "pinentry: remember the passphrase of %s: %v\n", keyinfo, err)
		}
		return
	}
	if err := sv.cache.Clear(ctx, keyinfo); err != nil {
		fmt.Fprintf(os.Stderr, "pinentry: forget the passphrase of %s: %v\n", keyinfo, err)
	}
}

func (sv *server) confirm(ctx context.Context, oneButton bool) error {
	dctx, cancel := sv.dialog(ctx)
	defer cancel()
	yes, err := sv.ui.Confirm(dctx, sv.s.req, oneButton)
	sv.s.req.Error = ""
	if err != nil {
		return sv.dialogFailed(dctx, err)
	}
	if !yes && !oneButton {
		return sv.fail(errCanceled, "Operation cancelled")
	}
	return sv.ok()
}

// dialogFailed answers a dialog that could not be shown or did not finish.
func (sv *server) dialogFailed(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, ErrNoDialogHost):
		if werr := sv.fail(errNoPinEntry, "No pinentry"); werr != nil {
			return werr
		}
		return errEnd
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return sv.fail(errTimeout, "Timeout")
	}
	fmt.Fprintf(os.Stderr, "pinentry: %v\n", err)
	return sv.fail(errGeneral, "General error")
}

func (sv *server) ok() error { return sv.line("OK") }

func (sv *server) fail(code int, text string) error {
	return sv.line(fmt.Sprintf("ERR %d %s <Pinentry>", code, text))
}

func (sv *server) line(text string) error {
	if _, err := io.WriteString(sv.out, text+"\n"); err != nil {
		return fmt.Errorf("pinentry: answer: %w", err)
	}
	return nil
}

// data writes value as D lines, escaped and split to the line limit; the
// lines are cleared once written, since value may be a passphrase.
func (sv *server) data(value []byte) error {
	buf := make([]byte, 0, maxLine)
	defer func() { clear(buf[:cap(buf)]) }()
	flush := func() error {
		buf = append(buf, '\n')
		_, err := sv.out.Write(buf)
		clear(buf)
		buf = buf[:0]
		if err != nil {
			return fmt.Errorf("pinentry: answer: %w", err)
		}
		return nil
	}
	for i, c := range value {
		if len(buf) == 0 {
			buf = append(buf, 'D', ' ')
		}
		switch c {
		case '%', '\r', '\n':
			buf = append(buf, '%', hex[c>>4], hex[c&0xf])
		default:
			buf = append(buf, c)
		}
		if len(buf) >= dataLinePayload || i == len(value)-1 {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	return nil
}

const hex = "0123456789ABCDEF"

// unescape decodes Assuan's %XX escapes; a malformed one stays as it is.
func unescape(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(n))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
