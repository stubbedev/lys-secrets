package vault

import (
	"fmt"
	"math"
	"time"
	"unicode/utf8"
)

type SendID string

type SendType uint32

const (
	SendText SendType = 0
	SendFile SendType = 1
	SendItem SendType = 2
)

func (t SendType) valid() bool { return t <= SendItem }

type Send struct {
	ID             SendID
	Type           SendType
	Name           string
	AccessCount    uint32
	MaxAccessCount uint32
	HasPassword    bool
	Disabled       bool
	Undecryptable  bool
	Deletion       time.Time
	Expiration     time.Time
}

type NewTextSend struct {
	Name           string
	Text           string
	Deletion       time.Time
	MaxAccessCount uint32
	Password       string
}

type CreatedSend struct {
	ID  SendID
	URL string
}

const (
	maxEncryptedSendName = 1000
	maxEncryptedSendText = 1000
	MinSendLifetime      = time.Minute
	MaxSendLifetime      = 31 * 24 * time.Hour
)

func (s NewTextSend) Validate(now time.Time) error {
	if err := validName("name", s.Name, maxEncryptedSendName); err != nil {
		return err
	}
	if err := validName("text", s.Text, maxEncryptedSendText); err != nil {
		return err
	}
	if !utf8.ValidString(s.Password) {
		return fmt.Errorf("%w: the password is not UTF-8", ErrInvalidInput)
	}
	if s.MaxAccessCount > math.MaxInt32 {
		return fmt.Errorf("%w: a maximum access count of %d exceeds %d", ErrInvalidInput, s.MaxAccessCount, math.MaxInt32)
	}
	if !s.Deletion.After(now.Add(MinSendLifetime)) || s.Deletion.After(now.Add(MaxSendLifetime)) {
		return fmt.Errorf("%w: the deletion date %s is not within %s and %s from now", ErrInvalidInput, s.Deletion.UTC().Format(time.RFC3339), MinSendLifetime, MaxSendLifetime)
	}
	return nil
}

func (id SendID) validate() error {
	if id == "" || !utf8.ValidString(string(id)) {
		return fmt.Errorf("%w: the Send id is empty or not UTF-8", ErrInvalidInput)
	}
	return nil
}

type wireSend struct {
	ID             string
	Type           uint32
	Name           string
	AccessCount    uint32
	MaxAccessCount uint32
	HasPassword    bool
	Disabled       bool
	Undecryptable  bool
	Deletion       int64
	Expiration     int64
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func timeOrZero(u int64) time.Time {
	if u == 0 {
		return time.Time{}
	}
	return time.Unix(u, 0)
}

func toWireSend(s Send) wireSend {
	return wireSend{
		ID: string(s.ID), Type: uint32(s.Type), Name: s.Name, AccessCount: s.AccessCount, MaxAccessCount: s.MaxAccessCount,
		HasPassword: s.HasPassword, Disabled: s.Disabled, Undecryptable: s.Undecryptable,
		Deletion: unixOrZero(s.Deletion), Expiration: unixOrZero(s.Expiration),
	}
}

func fromWireSend(w wireSend) (Send, error) {
	t := SendType(w.Type)
	if !t.valid() {
		return Send{}, fmt.Errorf("send %s has type %d", w.ID, w.Type)
	}
	if w.ID == "" {
		return Send{}, fmt.Errorf("a send named %q has no id", w.Name)
	}
	return Send{
		ID: SendID(w.ID), Type: t, Name: w.Name, AccessCount: w.AccessCount, MaxAccessCount: w.MaxAccessCount,
		HasPassword: w.HasPassword, Disabled: w.Disabled, Undecryptable: w.Undecryptable,
		Deletion: timeOrZero(w.Deletion), Expiration: timeOrZero(w.Expiration),
	}, nil
}
