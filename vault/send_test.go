package vault

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

func TestSends(t *testing.T) {
	deletion, expiration := time.Unix(1_800_000_000, 0), time.Unix(1_799_000_000, 0)
	want := []Send{
		{ID: "s1", Type: SendText, Name: "Wifi", AccessCount: 2, MaxAccessCount: 5, HasPassword: true, Deletion: deletion, Expiration: expiration},
		{ID: "s2", Type: SendFile, Name: "s2", Undecryptable: true, Disabled: true, Deletion: deletion},
	}
	host := &fakeHost{sends: want}
	_, c, _ := serve(t, host)
	got, err := c.Sends(ctx(t))
	if err != nil || len(got) != 2 {
		t.Fatalf("Sends = %+v, %v", got, err)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("send %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	host.with(func() { host.sends = nil })
	if got, err := c.Sends(ctx(t)); err != nil || len(got) != 0 {
		t.Errorf("no sends = %+v, %v", got, err)
	}
	if _, err := fromWireSend(wireSend{ID: "x", Type: 9}); err == nil {
		t.Error("a Send of type 9 was taken")
	}
	if _, err := fromWireSend(wireSend{Name: "x"}); err == nil {
		t.Error("a Send without an id was taken")
	}
}

func TestCreateTextSend(t *testing.T) {
	host := &fakeHost{}
	_, c, conn := serve(t, host)
	deletion := time.Now().Add(7 * 24 * time.Hour).Truncate(time.Second)
	created, err := c.CreateTextSend(ctx(t), NewTextSend{Name: "Wifi", Text: "hunter22", Deletion: deletion, MaxAccessCount: 3, Password: "pw"})
	if err != nil || created.ID != "s-new" || created.URL != "https://send.example/#/send/acc/key" {
		t.Fatalf("created = %+v, %v", created, err)
	}
	host.with(func() {
		if len(host.newSends) != 1 || host.newSends[0] != (NewTextSend{Name: "Wifi", Text: "hunter22", Deletion: deletion, MaxAccessCount: 3, Password: "pw"}) {
			t.Errorf("the host got %+v", host.newSends)
		}
	})
	obj := conn.Object(ServiceName, ServicePath)
	for what, args := range map[string][]any{
		"past deletion":   {"Wifi", "t", time.Now().Add(-time.Hour).Unix(), uint32(0), ""},
		"far deletion":    {"Wifi", "t", time.Now().Add(32 * 24 * time.Hour).Unix(), uint32(0), ""},
		"empty text":      {"Wifi", "", deletion.Unix(), uint32(0), ""},
		"empty name":      {"", "t", deletion.Unix(), uint32(0), ""},
		"long text":       {"Wifi", strings.Repeat("t", 688), deletion.Unix(), uint32(0), ""},
		"huge access cap": {"Wifi", "t", deletion.Unix(), uint32(math.MaxUint32), ""},
	} {
		err := decodeError(obj.CallWithContext(ctx(t), iface+".CreateTextSend", 0, args...).Err)
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: %v", what, err)
		}
	}
	if _, err := c.CreateTextSend(ctx(t), NewTextSend{Name: "Wifi", Text: "t"}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("the client sent a Send without a deletion date: %v", err)
	}
	host.with(func() {
		if len(host.newSends) != 1 {
			t.Errorf("a refused Send reached the host: %+v", host.newSends)
		}
	})
}

func TestDeleteSend(t *testing.T) {
	host := &fakeHost{}
	_, c, conn := serve(t, host)
	if err := c.DeleteSend(ctx(t), "s1"); err != nil {
		t.Errorf("delete = %v", err)
	}
	if err := c.DeleteSend(ctx(t), "s9"); !errors.Is(err, ErrNoSuchSend) {
		t.Errorf("delete an unknown Send = %v", err)
	}
	if err := c.DeleteSend(ctx(t), ""); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("the client sent an empty id: %v", err)
	}
	if err := decodeError(conn.Object(ServiceName, ServicePath).CallWithContext(ctx(t), iface+".DeleteSend", 0, "").Err); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("the daemon took an empty id: %v", err)
	}
	host.with(func() {
		if len(host.deleted) != 1 || host.deleted[0] != "s1" {
			t.Errorf("deleted %v", host.deleted)
		}
	})
}

func TestNewTextSendValidate(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	ok := NewTextSend{Name: strings.Repeat("n", 687), Text: strings.Repeat("t", 687), Deletion: now.Add(MaxSendLifetime), MaxAccessCount: math.MaxInt32, Password: "pw"}
	if err := ok.Validate(now); err != nil {
		t.Errorf("the largest Send is refused: %v", err)
	}
	for what, mutate := range map[string]func(*NewTextSend){
		"deletion now":       func(s *NewTextSend) { s.Deletion = now },
		"deletion in 1m":     func(s *NewTextSend) { s.Deletion = now.Add(MinSendLifetime) },
		"deletion past 31d":  func(s *NewTextSend) { s.Deletion = now.Add(MaxSendLifetime + time.Second) },
		"blank name":         func(s *NewTextSend) { s.Name = " " },
		"long name":          func(s *NewTextSend) { s.Name = strings.Repeat("n", 688) },
		"blank text":         func(s *NewTextSend) { s.Text = "\n" },
		"long text":          func(s *NewTextSend) { s.Text = strings.Repeat("t", 688) },
		"access past int32":  func(s *NewTextSend) { s.MaxAccessCount = math.MaxInt32 + 1 },
		"password not UTF-8": func(s *NewTextSend) { s.Password = "\xff" },
	} {
		s := ok
		s.Text = "secret text"
		mutate(&s)
		err := s.Validate(now)
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: %v", what, err)
		}
		if err != nil && (strings.Contains(err.Error(), "secret text") || strings.Contains(err.Error(), "pw")) {
			t.Errorf("%s: the error holds a value: %v", what, err)
		}
	}
}
